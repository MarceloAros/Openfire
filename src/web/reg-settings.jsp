<%--
  -
  - Copyright (C) 2004-2008 Jive Software. All rights reserved.
  -
  - Licensed under the Apache License, Version 2.0 (the "License");
  - you may not use this file except in compliance with the License.
  - You may obtain a copy of the License at
  -
  -     http://www.apache.org/licenses/LICENSE-2.0
  -
  - Unless required by applicable law or agreed to in writing, software
  - distributed under the License is distributed on an "AS IS" BASIS,
  - WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  - See the License for the specific language governing permissions and
  - limitations under the License.
--%>

<%@ page import="org.jivesoftware.openfire.XMPPServer,
                 org.jivesoftware.openfire.handler.IQRegisterHandler,
                 org.jivesoftware.openfire.session.LocalClientSession"
    errorPage="error.jsp"
%>
<%@ page import="java.util.regex.Pattern" %>
<%@ page import="java.util.*" %>
<%@ page import="org.jivesoftware.openfire.net.SASLAuthentication" %>
<%@ page import="org.jivesoftware.openfire.user.UserManager" %>
<%@ page import="org.jivesoftware.util.*" %>

<%@ taglib uri="admin" prefix="admin" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>

<jsp:useBean id="webManager" class="org.jivesoftware.util.WebManager"  />
<% webManager.init(request, response, session, application, out ); %>

<html>
<head>
<meta charset="UTF-8">
<title><fmt:message key="reg.settings.title"/></title>
<meta name="pageID" content="server-reg-and-login"/>
<meta name="helpPage" content="manage_registration_and_login_settings.html"/>
</head>
<body>

<% // Get parameters
    boolean save = request.getParameter("save") != null;
    boolean inbandEnabled = ParamUtils.getBooleanParameter(request, "inbandEnabled");
    boolean canChangePassword = ParamUtils.getBooleanParameter(request, "canChangePassword");
    boolean anonLogin = ParamUtils.getBooleanParameter(request, "anonLogin");
    String allowedIPs = request.getParameter("allowedIPs");
    String allowedAnonymIPs = request.getParameter("allowedAnonymIPs");
    String blockedIPs = request.getParameter("blockedIPs");
    String newConsumerKey = request.getParameter("newConsumerKey");
    String newConsumerSecret = request.getParameter("newConsumerSecret");
    int newConsumerAuthorizedCreations = ParamUtils.getIntParameter(request, "newConsumerAuthorizedCreations", 0);
    // Get an IQRegisterHandler:
    IQRegisterHandler regHandler = XMPPServer.getInstance().getIQRegisterHandler();
    Cookie csrfCookie = CookieUtils.getCookie(request, "csrf");
    String csrfParam = ParamUtils.getParameter(request, "csrf");

    final Enumeration<String> parameterNames = request.getParameterNames();
    final String mechEnabledPrefix = "mech-enabled-";
    final List<String> mechsEnabled = new ArrayList<>();
    while ( parameterNames.hasMoreElements() )
    {
        final String parameterName = parameterNames.nextElement();
        if (parameterName.startsWith( mechEnabledPrefix ))
        {
            mechsEnabled.add( parameterName.substring( mechEnabledPrefix.length() ) );
        }
    }

    if (save) {
        if (csrfCookie == null || csrfParam == null || !csrfCookie.getValue().equals(csrfParam)) {
            save = false;
        }
    }
    csrfParam = StringUtils.randomString(15);
    CookieUtils.setCookie(request, response, "csrf", csrfParam, -1);
    pageContext.setAttribute("csrf", csrfParam);

    if (save) {
        regHandler.setInbandRegEnabled(inbandEnabled);

        if (newConsumerKey != null && newConsumerSecret != null && newConsumerAuthorizedCreations != 0){
            regHandler.insertConsumer(newConsumerKey, newConsumerSecret, newConsumerAuthorizedCreations);
        }

        regHandler.setCanChangePassword(canChangePassword);
        JiveGlobals.setProperty("xmpp.auth.anonymous", Boolean.toString(anonLogin));

        // Build a Map with the allowed IP addresses
        Pattern pattern = Pattern.compile("(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.)" +
                "(?:(?:\\*|25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){2}" +
                "(?:\\*|25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)");
        Set<String> allowedSet = new HashSet<String>();
        StringTokenizer tokens = new StringTokenizer(allowedIPs, ", ");
        while (tokens.hasMoreTokens()) {
            String address = tokens.nextToken().trim();
            if (pattern.matcher(address).matches()) {
                allowedSet.add( address );
            }
        }


        Set<String> allowedAnonymousSet = new HashSet<String>();
        StringTokenizer tokens1 = new StringTokenizer(allowedAnonymIPs, ", ");
        while (tokens1.hasMoreTokens()) {
            String address = tokens1.nextToken().trim();
            if (pattern.matcher(address).matches()) {
                allowedAnonymousSet.add( address );
            }
        }

        Set<String> blockedSet = new HashSet<String>();
        StringTokenizer tokens2 = new StringTokenizer(blockedIPs, ", ");
        while (tokens2.hasMoreTokens()) {
            String address = tokens2.nextToken().trim();
            if (pattern.matcher(address).matches()) {
                blockedSet.add( address );
            }
        }
        LocalClientSession.setWhitelistedIPs( allowedSet );
        LocalClientSession.setWhitelistedAnonymousIPs( allowedAnonymousSet );
        LocalClientSession.setBlacklistedIPs( blockedSet );
        SASLAuthentication.setEnabledMechanisms( mechsEnabled );

        // Log the event
        webManager.logEvent("edited registration settings", "inband enabled = "+inbandEnabled+"\ncan change password = "+canChangePassword+"\nanon login = "+anonLogin+"\nallowed ips = "+allowedIPs+"\nblocked ips = "+blockedIPs+"\nSASL mechanisms enabled = "+ mechsEnabled);
    }

    // Reset the value of page vars:
    inbandEnabled = regHandler.isInbandRegEnabled();
    canChangePassword = regHandler.canChangePassword();
    anonLogin = JiveGlobals.getBooleanProperty( "xmpp.auth.anonymous" );
    // Encode the allowed IP addresses
    StringBuilder buf = new StringBuilder();
    Iterator<String> iter = org.jivesoftware.openfire.session.LocalClientSession.getWhitelistedIPs().iterator();
    if (iter.hasNext()) {
        buf.append(iter.next());
    }
    while (iter.hasNext()) {
        buf.append(", ").append(iter.next());
    }
    allowedIPs = buf.toString();

    StringBuilder buf1 = new StringBuilder();
    Iterator<String> iter1 = org.jivesoftware.openfire.session.LocalClientSession.getWhitelistedAnonymousIPs().iterator();
    if (iter1.hasNext()) {
        buf1.append(iter1.next());
    }
    while (iter1.hasNext()) {
        buf1.append(", ").append(iter1.next());
    }
    allowedAnonymIPs = buf1.toString();

    StringBuilder buf2 = new StringBuilder();
    Iterator<String> iter2 = org.jivesoftware.openfire.session.LocalClientSession.getBlacklistedIPs().iterator();
    if (iter2.hasNext()) {
        buf2.append(iter2.next());
    }
    while (iter2.hasNext()) {
        buf2.append(", ").append(iter2.next());
    }
    blockedIPs = buf2.toString();

    // Fill arraylist with data form consumers
    ArrayList<ArrayList<String>> consumers = regHandler.getConsumers();

    pageContext.setAttribute( "consumers",          consumers);
    pageContext.setAttribute( "readOnly",           UserManager.getUserProvider().isReadOnly() );
    pageContext.setAttribute( "inbandEnabled",      inbandEnabled );
    pageContext.setAttribute( "canChangePassword",  canChangePassword );
    pageContext.setAttribute( "anonLogin",          anonLogin );
    pageContext.setAttribute( "blockedIPs",         blockedIPs);
    pageContext.setAttribute( "allowedIPs",         allowedIPs );
    pageContext.setAttribute( "allowedAnonymIPs",   allowedAnonymIPs );
    pageContext.setAttribute( "saslEnabledMechanisms",     SASLAuthentication.getEnabledMechanisms() );
    pageContext.setAttribute( "saslImplementedMechanisms", SASLAuthentication.getImplementedMechanisms() );
    pageContext.setAttribute( "saslSupportedMechanisms",   SASLAuthentication.getSupportedMechanisms() );

    final SortedSet<String> union = new TreeSet<>();
    union.addAll( SASLAuthentication.getEnabledMechanisms() );
    union.addAll( SASLAuthentication.getImplementedMechanisms() );
    pageContext.setAttribute( "saslConsideredOrImplementedMechanisms", union );
%>

<p>
<fmt:message key="reg.settings.info" />
</p>

<form action="reg-settings.jsp">
    <input type="hidden" name="csrf" value="${csrf}">

<% if (save) { %>

    <admin:infoBox type="success">
        <fmt:message key="reg.settings.update" />
    </admin:infoBox>

<% } %>

<!-- BEGIN registration settings -->
    <fmt:message key="reg.settings.inband_account" var="inband_account_boxtitle"/>
    <admin:contentBox title="${inband_account_boxtitle}">
        <p><fmt:message key="reg.settings.inband_account_info" /></p>
        <c:if test="${readOnly}">
            <admin:infoBox type="info"><fmt:message key="reg.settings.inband_account_readonly" /></admin:infoBox>
        </c:if>
        <table cellpadding="3" cellspacing="0" border="0">
            <tr>
                <td width="1%"><input type="radio" name="inbandEnabled" value="true" id="rb01" ${inbandEnabled ? 'checked' : ''} ${readOnly ? 'disabled' : ''}></td>
                <td width="99%"><label for="rb01"><b><fmt:message key="reg.settings.enable" /></b> -<fmt:message key="reg.settings.auto_create_user" /></label></td>
            </tr>
            <tr>
                <td width="1%"><input type="radio" name="inbandEnabled" value="false" id="rb02" ${inbandEnabled ?  '' : 'checked'} ${readOnly ? 'disabled' : ''}></td>
                <td width="99%"><label for="rb02"><b><fmt:message key="reg.settings.disable" /></b> - <fmt:message key="reg.settings.not_auto_create" /></label></td>
            </tr>
        </table>
    </admin:contentBox>
<!-- *********************************************************** -->
    <fmt:message key="reg.setting.signing_forms" var="signing_forms_boxtitle" />
    <admin:contentBox title="${signing_forms_boxtitle}">
        <p>Signature forms (XEP-0348) describe the mechanism by which forms can be signed using other credentials. This is used in conjunction with In-Band Regitration, in which special credentials are created with named accounts to create new accounts with XMPP, with a limit on the number of accounts that can be created. This method can be used by the manufacturers of devices for Internet of Things, so that the devices can create accounts automatically on the XMPP servers in an orderly manner, and customers can manage and control their accounts created separately. It also offers a mechanism by which the operators of the server can create who is responsible for the creation of the account and to what extent.</p>
        <br>
        <table cellpadding="3" cellspacing="0" border="0">
            <tr>
                <td width="1%"><input type="radio" name="oAuthEnabled" value="true" id="rb11" ${inbandEnabled ? 'checked' : ''} ${readOnly ? 'disabled' : ''}></td>
                <td width="99%"><label for="rb11"><b><fmt:message key="reg.settings.enable" /></b> -<fmt:message key="reg.settings.auto_create_user.oauth" /></label></td>
            </tr>
            <tr>
                <td width="1%"><input type="radio" name="oAuthEnabled" value="false" id="rb12" ${inbandEnabled ?  '' : 'checked'} ${readOnly ? 'disabled' : ''}></td>
                <td width="99%"><label for="rb12"><b><fmt:message key="reg.settings.disable" /></b> - <fmt:message key="reg.settings.not_auto_create_user.oauth" /></label></td>
            </tr>
        </table>

        <br>
        <table>
            <tr>
                <td><b>Signature Key:</b><br>
                    <input id=consumerKey type="text" size="60" maxlength="100" name="newConsumerKey" readonly>
                </td>
            </tr>
            <tr>
                <td><b>Signtature Secret Key:</b> <br>
                    <input id="consumerSecret" type="text" size="60" maxlength="100" name="newConsumerSecret" readonly>
                </td>
                <td>
                    <br>
                    <input type="button" onclick="generateCredentials();" name="Generate Credentials" value="Generate credentials">
                </td>
            </tr>
            <tr>
                <td>
                    <b>Authorized creations</b><br>
                    <input type="text" size="7" maxlength="7" name="newConsumerAuthorizedCreations" onkeypress='validate(event)' >
                </td>
            </tr>
        </table>

        <input id="submitConsumerCredentials" type="submit" name="save" value="Guardar credencial" disabled>

        <br><br>

        <div class="jive-table">
            <table cellpadding="0" cellspacing="0" border="0" width="100%">
                <tr>
                    <th nowrap>Consumer Key</th>
                    <th nowrap>Consumer Secret</th>
                    <th nowrap>Authorized creations</th>
                    <th nowrap>Used creations</th>
                </tr>
                <c:forEach items="${consumers}" var="row">
                    <tr>
                    <c:forEach items="${row}" var="cell">
                        <td>${cell}</td>
                    </c:forEach>
                    </tr>
                </c:forEach>
            </table>
        </div>

        <script>
            function uuidv4() {
                return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
                    return v.toString(16);
                });
            }
            function SHA256(s){
                var chrsz   = 8;
                var hexcase = 0;
                function safe_add (x, y) {
                    var lsw = (x & 0xFFFF) + (y & 0xFFFF);
                    var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
                    return (msw << 16) | (lsw & 0xFFFF);
                }
                function S (X, n) { return ( X >>> n ) | (X << (32 - n)); }
                function R (X, n) { return ( X >>> n ); }
                function Ch(x, y, z) { return ((x & y) ^ ((~x) & z)); }
                function Maj(x, y, z) { return ((x & y) ^ (x & z) ^ (y & z)); }
                function Sigma0256(x) { return (S(x, 2) ^ S(x, 13) ^ S(x, 22)); }
                function Sigma1256(x) { return (S(x, 6) ^ S(x, 11) ^ S(x, 25)); }
                function Gamma0256(x) { return (S(x, 7) ^ S(x, 18) ^ R(x, 3)); }
                function Gamma1256(x) { return (S(x, 17) ^ S(x, 19) ^ R(x, 10)); }
                function core_sha256 (m, l) {
                    var K = new Array(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2);
                    var HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
                    var W = new Array(64);
                    var a, b, c, d, e, f, g, h, i, j;
                    var T1, T2;
                    m[l >> 5] |= 0x80 << (24 - l % 32);
                    m[((l + 64 >> 9) << 4) + 15] = l;
                    for (var i = 0; i < m.length; i += 16) {
                        a = HASH[0];
                        b = HASH[1];
                        c = HASH[2];
                        d = HASH[3];
                        e = HASH[4];
                        f = HASH[5];
                        g = HASH[6];
                        h = HASH[7];
                        for (var j = 0; j < 64; j++) {
                            if (j < 16) W[j] = m[j + i];
                            else W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);
                            T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
                            T2 = safe_add(Sigma0256(a), Maj(a, b, c));
                            h = g;
                            g = f;
                            f = e;
                            e = safe_add(d, T1);
                            d = c;
                            c = b;
                            b = a;
                            a = safe_add(T1, T2);
                        }
                        HASH[0] = safe_add(a, HASH[0]);
                        HASH[1] = safe_add(b, HASH[1]);
                        HASH[2] = safe_add(c, HASH[2]);
                        HASH[3] = safe_add(d, HASH[3]);
                        HASH[4] = safe_add(e, HASH[4]);
                        HASH[5] = safe_add(f, HASH[5]);
                        HASH[6] = safe_add(g, HASH[6]);
                        HASH[7] = safe_add(h, HASH[7]);
                    }
                    return HASH;
                }
                function str2binb(str) {
                    var bin = Array();
                    var mask = (1 << chrsz) - 1;
                    for (var i = 0; i < str.length * chrsz; i += chrsz) {
                        bin[i >> 5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i % 32);
                    }
                    return bin;
                }
                function Utf8Encode(string) {
                    string = string.replace(/\r\n/g, "\n");
                    var utftext = "";
                    for (var n = 0; n < string.length; n++) {
                        var c = string.charCodeAt(n);
                        if (c < 128) {
                            utftext += String.fromCharCode(c);
                        }
                        else if ((c > 127) && (c < 2048)) {
                            utftext += String.fromCharCode((c >> 6) | 192);
                            utftext += String.fromCharCode((c & 63) | 128);
                        }
                        else {
                            utftext += String.fromCharCode((c >> 12) | 224);
                            utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                            utftext += String.fromCharCode((c & 63) | 128);
                        }
                    }
                    return utftext;
                }

                function binb2hex(binarray) {
                    var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
                    var str = "";
                    for (var i = 0; i < binarray.length * 4; i++) {

                        str += hex_tab.charAt((binarray[i >> 2] >> ((3 - i % 4) * 8 + 4)) & 0xF) +

                            hex_tab.charAt((binarray[i >> 2] >> ((3 - i % 4) * 8)) & 0xF);

                    }
                    return str;
                }
                s = Utf8Encode(s);
                return binb2hex(core_sha256(str2binb(s), s.length * chrsz));
            }

            function generateCredentials(){
                document.getElementById('consumerKey').value = SHA256(uuidv4());
                document.getElementById('consumerSecret').value = SHA256(uuidv4());
                document.getElementById('submitConsumerCredentials').disabled = false;
            }

            function validate(evt) {
                var theEvent = evt || window.event;

                // Handle paste
                if (theEvent.type === 'paste') {
                    key = event.clipboardData.getData('text/plain');
                } else {
                    // Handle key press
                    var key = theEvent.keyCode || theEvent.which;
                    key = String.fromCharCode(key);
                }
                var regex = /[0-9]|\./;
                if( !regex.test(key) ) {
                    theEvent.returnValue = false;
                    if(theEvent.preventDefault) theEvent.preventDefault();
                }
            }
        </script>

        <%--TODO: lectura y escritura de campos de la base de datos--%>
        <%--TODO: Soporte mutli-idoma--%>
        <!-- FIN: Modificación -->
    </admin:contentBox>
<!-- *********************************************************** -->
    <fmt:message key="reg.settings.change_password" var="change_password_boxtitle"/>
    <admin:contentBox title="${change_password_boxtitle}">
        <p><fmt:message key="reg.settings.change_password_info" /></p>
        <c:if test="${readOnly}">
            <admin:infoBox type="info"><fmt:message key="reg.settings.change_password_readonly" /></admin:infoBox>
        </c:if>
        <table cellpadding="3" cellspacing="0" border="0">
            <tr>
                <td width="1%"><input type="radio" name="canChangePassword" value="true" id="rb03" ${canChangePassword ? 'checked' : ''} ${readOnly ? 'disabled' : ''}></td>
                <td width="99%"><label for="rb03"><b><fmt:message key="reg.settings.enable" /></b> - <fmt:message key="reg.settings.can_change" /></label></td>
            </tr>
            <tr>
                <td width="1%"><input type="radio" name="canChangePassword" value="false" id="rb04" ${canChangePassword ? '' : 'checked'} ${readOnly ? 'disabled' : ''}></td>
                <td width="99%"><label for="rb04"><b><fmt:message key="reg.settings.disable" /></b> - <fmt:message key="reg.settings.cannot_change" /></label></td>
            </tr>
        </table>
    </admin:contentBox>

    <fmt:message key="reg.settings.anonymous_login" var="anonymous_login_boxtitle"/>
    <admin:contentBox title="${anonymous_login_boxtitle}">
        <p><fmt:message key="reg.settings.anonymous_login_info" /></p>
        <table cellpadding="3" cellspacing="0" border="0">
            <tr>
                <td width="1%"><input type="radio" name="anonLogin" value="true" id="rb05" ${anonLogin ? 'checked' : ''}></td>
                <td width="99%"><label for="rb05"><b><fmt:message key="reg.settings.enable" /></b> - <fmt:message key="reg.settings.anyone_login" /></label></td>
            </tr>
            <tr>
                <td width="1%"><input type="radio" name="anonLogin" value="false" id="rb06" ${anonLogin ? '' : 'checked'}></td>
                <td width="99%"><label for="rb06"><b><fmt:message key="reg.settings.disable" /></b> - <fmt:message key="reg.settings.only_registered_login" /></label></td>
            </tr>
        </table>
    </admin:contentBox>

    <fmt:message key="reg.settings.allowed_ips" var="allowed_ips_boxtitle"/>
    <admin:contentBox title="${allowed_ips_boxtitle}">
        <p><fmt:message key="reg.settings.allowed_ips_blocked_info" /></p>
        <table cellpadding="3" cellspacing="0" border="0">
            <tr>
                <td valign='top'><b><fmt:message key="reg.settings.ips_blocked" /></b></td>
                <td><textarea name="blockedIPs" cols="40" rows="3" wrap="virtual"><c:if test="${not empty blockedIPs}"><c:out value="${blockedIPs}"/></c:if></textarea></td>
            </tr>
        </table>

        <p><fmt:message key="reg.settings.allowed_ips_info" /></p>
        <table cellpadding="3" cellspacing="0" border="0">
            <tr>
                <td><textarea name="allowedIPs" cols="40" rows="3" wrap="virtual"><c:if test="${not empty allowedIPs}"><c:out value="${allowedIPs}"/></c:if></textarea></td>
            </tr>
            <tr>
                <td valign='top'><b><fmt:message key="reg.settings.ips_anonymous" /></b></td>
                <td><textarea name="allowedAnonymIPs" cols="40" rows="3" wrap="virtual"><c:if test="${not empty allowedAnonymIPs}"><c:out value="${allowedAnonymIPs}"/></c:if></textarea></td>
            </tr>
        </table>
    </admin:contentBox>

    <fmt:message key="reg.settings.sasl_mechanisms" var="sasl_mechanism_boxtitle"/>
    <admin:contentBox title="${sasl_mechanism_boxtitle}">
        <p><fmt:message key="reg.settings.sasl_mechanisms_info" /></p>
        <table class="jive-table" cellpadding="3" cellspacing="0" border="0">
            <tr>
                <th align="center" width="1%"><fmt:message key="reg.settings.sasl_mechanisms_columntitle_enabled" /></th>
                <th align="left" width="20%"><fmt:message key="reg.settings.sasl_mechanisms_columntitle_name" /></th>
                <th align="left"><fmt:message key="reg.settings.sasl_mechanisms_columntitle_description" /></th>
                <th align="center" width="5%" style="text-align: center"><fmt:message key="reg.settings.sasl_mechanisms_columntitle_implementation" /></th>
                <th align="center" width="5%" style="text-align: center"><fmt:message key="reg.settings.sasl_mechanisms_columntitle_supported" /></th>
            </tr>
            <c:forEach items="${saslConsideredOrImplementedMechanisms}" var="mechanism" varStatus="status">
                <c:set var="idForForm">mech-enabled-<c:out value="${mechanism}"/></c:set>
                <c:set var="description"><fmt:message key="reg.settings.description.${mechanism}" /></c:set>
                <c:choose>
                    <c:when test="${fn:startsWith(description,'???')}">
                        <c:set var="description"><fmt:message key="reg.settings.description.none" /></c:set>
                    </c:when>
                </c:choose>
                <c:set var="enabled" value="${saslEnabledMechanisms.contains(mechanism)}"/>
                <c:set var="implemented" value="${saslImplementedMechanisms.contains(mechanism)}"/>
                <c:set var="supported" value="${saslSupportedMechanisms.contains(mechanism)}"/>
                <tr class="${ ( (status.index + 1) % 2 ) eq 0 ? 'jive-even' : 'jive-odd'}">
                    <td align="center"><input type="checkbox" name="${idForForm}" id="${idForForm}" ${enabled ? 'checked' : ''}/></td>
                    <td align="left"><label for="${idForForm}"><c:out value="${mechanism}"/></label></td>
                    <td align="left"><c:out value="${description}"/></td>
                    <td align="center"><c:if test="${implemented}"><img src="images/check-16x16.gif" width="16" height="16" border="0" alt=""/></c:if></td>
                    <td align="center"><c:if test="${supported}"><img src="images/check-16x16.gif" width="16" height="16" border="0" alt=""/></c:if></td>
                </tr>
            </c:forEach>
        </table>
    </admin:contentBox>

    <input type="submit" name="save" value="<fmt:message key="global.save_settings" />">
    <!-- END registration settings -->

</form>

</body>

</html>
<td valign='top'><b><fmt:message key="reg.settings.ips_all" /></b></td>
