# Author: Jose Gonzalez
# Modified: Gamatech
import sys

from org.gluu.oxauth.service.net import HttpService
from java.lang import System
from java.net import URLDecoder, URLEncoder
from java.util import Arrays, ArrayList, Collections, HashMap
from javax.faces.application import FacesMessage
from javax.faces.context import FacesContext
from javax.servlet.http import Cookie
from org.gluu.jsf2.message import FacesMessages
from org.gluu.model import SimpleCustomProperty
from org.gluu.model.custom.script import CustomScriptType
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.service import AuthenticationService, UserService, RequestParameterService
from org.gluu.oxauth.service.custom import CustomScriptService
from org.gluu.oxauth.util import ServerUtil
from org.gluu.persist import PersistenceEntryManager
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.util import StringHelper
from org.oxauth.persistence.model.configuration import GluuConfiguration
from org.apache.http.params import CoreConnectionPNames

try:
    import json
except ImportError:
    import simplejson as json


class PersonAuthentication(PersonAuthenticationType):

    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis
        self.ACR_SG = "super_gluu"
        self.PREV_LOGIN_SETTING = "prevLoginsCookieSettings"
        
        self.modulePrefix = "pwdless-external_"

    def init(self, customScript, configurationAttributes): 
        print "Passwordless. init called"
        self.illion_url = configurationAttributes.get("illion_url").getValue2()
        self.authenticators = {}
        self.uid_attr = self.getLocalPrimaryKey()
        
        self.prevLoginsSettings = self.computePrevLoginsSettings(configurationAttributes.get(self.PREV_LOGIN_SETTING))

        custScriptService = CdiUtil.bean(CustomScriptService)
        self.scriptsList = custScriptService.findCustomScripts(Collections.singletonList(CustomScriptType.PERSON_AUTHENTICATION), "oxConfigurationProperty", "displayName", "oxEnabled")
        
        print "Passwordless. init. Initialized successfully"
        return True

    def destroy(self, configurationAttributes):
        return True

    def getApiVersion(self):
        return 11

    def getAuthenticationMethodClaims(self, configurationAttributes):
        return None

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        print "Passwordless. authenticate for step %d" % step

        userService = CdiUtil.bean(UserService)
        authenticationService = CdiUtil.bean(AuthenticationService)
        identity = CdiUtil.bean(Identity)
        session_attributes = identity.getSessionId().getSessionAttributes()

        if step == 1:
            user_name = identity.getCredentials().getUsername()
            state = session_attributes.get("state")
            # print "Passwordless. authenticate. State is %s" % state
            if StringHelper.isNotEmptyString(user_name):

                foundUser = userService.getUserByAttribute(self.uid_attr, user_name)
                
                if foundUser == None:
                    print "Passwordless. Unknown username '%s'" % user_name
                elif authenticationService.authenticate(user_name):
                    verify_illion_auth = self.verifyIllionState(self.illion_url, user_name, state)
                    if verify_illion_auth == user_name:
                        return True
                    else:
                        return False
                else:
                    self.setError("Wrong username or password")
        else:
            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        print "Passwordless. prepareForStep %d" % step

        identity = CdiUtil.bean(Identity)
        session_attributes = identity.getSessionId().getSessionAttributes()
        
        if step == 1:
            try:
                loginHint = session_attributes.get("login_hint")
                print "Passwordless. prepareForStep. Login hint is %s" % loginHint
                state = session_attributes.get("state")
                print "Passwordless. prepareForStep. State is %s" % state
                isLoginHint = loginHint != None
                
                if self.prevLoginsSettings == None:
                    if isLoginHint:
                        identity.setWorkingParameter("loginHint", loginHint)
                else:
                    users = self.getCookieValue()    
                    
                    if isLoginHint:
                        
                        idx = self.findUid(loginHint, users) 
                        if idx >= 0:
                            u = users.pop(idx)
                            users.insert(0, u)
                        else:
                            identity.setWorkingParameter("loginHint", loginHint)
                    
                    if len(users) > 0:
                        identity.setWorkingParameter("users", json.dumps(users, separators=(',', ':')))
            
                # In login.xhtml both loginHint and users are used to properly display the login form
            except:
                print "Passwordless. prepareForStep. Error!", sys.exc_info()[1]
                
            return True

    def getExtraParametersForStep(self, configurationAttributes, step):
        return None

    def getCountAuthenticationSteps(self, configurationAttributes):
        return 1

    def getPageForStep(self, configurationAttributes, step):
        return "/passwordless/login.xhtml"

    def getNextStep(self, configurationAttributes, requestParameters, step):
        return -1

    def logout(self, configurationAttributes, requestParameters):
        return True

# Miscelaneous

    def getLocalPrimaryKey(self):
        entryManager = CdiUtil.bean(PersistenceEntryManager)
        config = GluuConfiguration()
        config = entryManager.find(config.getClass(), "ou=configuration,o=gluu")
        # Pick (one) attribute where user id is stored (e.g. uid/mail)
        uid_attr = config.getOxIDPAuthentication().get(0).getConfig().getPrimaryKey()
        print "Passwordless. init. uid attribute is '%s'" % uid_attr
        return uid_attr

    def setError(self, msg):
        facesMessages = CdiUtil.bean(FacesMessages)
        facesMessages.setKeepMessages()
        facesMessages.clear()
        facesMessages.add(FacesMessage.SEVERITY_ERROR, msg)

    def getConfigurationAttributes(self, acr, scriptsList):

        configMap = HashMap()
        for customScript in scriptsList:
            if customScript.getName() == acr:
                for prop in customScript.getConfigurationProperties():
                    configMap.put(prop.getValue1(), SimpleCustomProperty(prop.getValue1(), prop.getValue2()))

        print "Passwordless. getConfigurationAttributes. %d configuration properties were found for %s" % (configMap.size(), acr)
        return configMap

    def simulateFirstStep(self, requestParameters, acr):
        # To simulate 1st step, there is no need to call:
        # getPageforstep (no need as user/pwd won't be shown again)
        # isValidAuthenticationMethod (by restriction, it returns True)
        # prepareForStep (by restriction, it returns True)
        # getExtraParametersForStep (by restriction, it returns None)
        print "Passwordless. simulateFirstStep. Calling authenticate (step 1) for %s module" % acr
        if acr in self.authenticators:
            module = self.authenticators[acr]
            auth = module.authenticate(module.configAttrs, requestParameters, 1)
            print "Passwordless. simulateFirstStep. returned value was %s" % auth
            
    def computePrevLoginsSettings(self, customProperty):
        settings = None
        if customProperty == None:
            print "Passwordless. Previous logins feature is not configured. Set config property '%s' if desired" % self.PREV_LOGIN_SETTING
        else:
            try:
                settings = json.loads(customProperty.getValue2())
                if settings['enabled']:
                    print "Passwordless. PrevLoginsSettings are %s" % settings
                else:
                    settings = None
                    print "Passwordless. Previous logins feature is disabled"
            except:
                print "Passwordless. Unparsable config property '%s'" % self.PREV_LOGIN_SETTING
            
        return settings
        
    def getCookieValue(self):
        ulist = []
        coo = None
        httpRequest = ServerUtil.getRequestOrNull()
        
        if httpRequest != None:
            for cookie in httpRequest.getCookies():
                if cookie.getName() == self.prevLoginsSettings['cookieName']:
                   coo = cookie
        
        if coo == None:
            print "Passwordless. getCookie. No cookie found"
        else:
            print "Passwordless. getCookie. Found cookie"
            forgetMs = self.prevLoginsSettings['forgetEntriesAfterMinutes'] * 60 * 1000
            
            try:
                now = System.currentTimeMillis()
                value = URLDecoder.decode(coo.getValue(), "utf-8")
                # value is an array of objects with properties: uid, displayName, lastLogon
                value = json.loads(value)
                
                for v in value:
                    if now - v['lastLogon'] < forgetMs:
                        ulist.append(v)        
                # print "==========", ulist
            except:
                print "Passwordless. getCookie. Unparsable value, dropping cookie..."
            
        return ulist

    def findUid(self, uid, users):
        
        i = 0
        idx = -1
        for user in users:
            if user['uid'] == uid:
                idx = i
                break
            i += 1
        return idx
    
    def verifyIllionState(self, remote_url, username, state):
        # print "Passwordless. remote_url: '%s'" % remote_url
        httpService = CdiUtil.bean(HttpService)
        http_client = httpService.getHttpsClient()
        http_client_params = http_client.getParams()
        http_client_params.setIntParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, 15 * 1000)
        # requestParameterService = CdiUtil.bean(RequestParameterService)
        # illion_service_request_uri = remote_url
        # illion_service_headers = { "Accept": "application/json" }
        # parametersMap = HashMap()
        # parametersMap.put("username", username)
        # parametersMap.put("state", state)
        # illion_service_request_uri = requestParameterService.parametersAsString(parametersMap)
        # illion_service_request_uri = remote_url + "?" + illion_service_request_uri
        illion_service_request_uri = remote_url + "?username=" + username + "&state=" + state
        # print "url '%s'" % illion_service_request_uri
        try:
            http_service_response = httpService.executeGet(http_client, illion_service_request_uri)
            http_response = http_service_response.getHttpResponse()
        except:
            print "Passwordless. Exception: ", sys.exc_info()[1]
            return None

        try:
            if not httpService.isResponseStastusCodeOk(http_response):
                print "Passwordless. Get invalid response from validation server: ", str(http_response.getStatusLine().getStatusCode())
                httpService.consume(http_response)
                return None
            response_bytes = httpService.getResponseContent(http_response)
            response_string = httpService.convertEntityToString(response_bytes)
            httpService.consume(http_response)
        finally:
            http_service_response.closeConnection()

        if response_string == None:
            print "Passwordless. Get empty response from location server"
            return None
        
        response_string = response_string.replace("[", "")  
        response_string = response_string.replace("]", "")   
        # print "response xxxxxxxxxxxxxxxxxxxxxx '%s'" % response_string  
        response = json.loads(response_string)
        
        if not StringHelper.equalsIgnoreCase(response['username'], username):
            print "Passwordless. Get response with status: '%s'" % response['username']
            return None

        print "Passwordless. Get response with status: '%s'" % response['username']
        return response['username']
            
    def persistCookie(self, user):
        try:
            now = System.currentTimeMillis()
            uid = user.getUserId()
            dname = user.getAttribute("displayName")
            
            users = self.getCookieValue()
            idx = self.findUid(uid, users)
            
            if idx >= 0:
                u = users.pop(idx)
            else:
                u = { 'uid': uid, 'displayName': '' if dname == None else dname }
            u['lastLogon'] = now
            
            # The most recent goes first :)
            users.insert(0, u)
            
            excess = len(users) - self.prevLoginsSettings['maxListSize']            
            if excess > 0:
                print "Passwordless. persistCookie. Shortening list..."
                users = users[:self.prevLoginsSettings['maxListSize']]
            
            value = json.dumps(users, separators=(',', ':'))
            value = URLEncoder.encode(value, "utf-8")
            coo = Cookie(self.prevLoginsSettings['cookieName'], value)
            coo.setSecure(True)
            coo.setHttpOnly(True)
            # One week
            coo.setMaxAge(7 * 24 * 60 * 60)
            
            response = self.getHttpResponse()
            if response != None:
                print "Passwordless. persistCookie. Adding cookie to response"
                response.addCookie(coo)
        except:
            print "Passwordless. persistCookie. Exception: ", sys.exc_info()[1]

    def getHttpResponse(self):
        try:
            return FacesContext.getCurrentInstance().getExternalContext().getResponse()
        except:
            print "Passwordless. Error accessing HTTP response object: ", sys.exc_info()[1]
            return None
        
