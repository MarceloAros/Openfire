/*
 * Copyright (C) 2005-2008 Jive Software. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jivesoftware.openfire.handler;

import gnu.inet.encoding.Stringprep;
import gnu.inet.encoding.StringprepException;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.sql.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.QName;
import org.jivesoftware.database.DbConnectionManager;
import org.jivesoftware.openfire.IQHandlerInfo;
import org.jivesoftware.openfire.PacketException;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.disco.ServerFeaturesProvider;
import org.jivesoftware.openfire.group.GroupManager;
import org.jivesoftware.openfire.roster.RosterManager;
import org.jivesoftware.openfire.session.ClientSession;
import org.jivesoftware.openfire.session.Session;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserAlreadyExistsException;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.forms.DataForm;
import org.xmpp.forms.FormField;
import org.xmpp.packet.IQ;
import org.xmpp.packet.JID;
import org.xmpp.packet.PacketError;
import org.xmpp.packet.StreamError;

/**
 * Implements the TYPE_IQ jabber:iq:register protocol (plain only). Clients
 * use this protocol to register a user account with the server.
 * A 'get' query runs a register probe to obtain the fields needed
 * for registration. Return the registration form.
 * A 'set' query attempts to create a new user account
 * with information given in the registration form.
 * <h2>Assumptions</h2>
 * This handler assumes that the request is addressed to the server.
 * An appropriate TYPE_IQ tag matcher should be placed in front of this
 * one to route TYPE_IQ requests not addressed to the server to
 * another channel (probably for direct delivery to the recipient).
 * <h2>Compatibility</h2>
 * The current behavior is designed to emulate jabberd1.4. However
 * this behavior differs significantly from JEP-0078 (non-SASL registration).
 * In particular, authentication (IQ-Auth) must return an error when a user
 * request is made to an account that doesn't exist to trigger auto-registration
 * (JEP-0078 explicitly recommends against this practice to prevent hackers
 * from probing for legitimate accounts).
 *
 * @author Iain Shigeoka
 */
public class IQRegisterHandler extends IQHandler implements ServerFeaturesProvider {

    private static final Logger Log = LoggerFactory.getLogger(IQRegisterHandler.class);

    private static boolean registrationEnabled;
    private static boolean canChangePassword;
    private static Element probeResult;
    private static boolean oAuthEnabled; // Habilitador de soporte XEP-0348

    private UserManager userManager;
    private RosterManager rosterManager;

    String[] consumerData;
    private static String oAuthConsumerSecret;
    private static Map<String, String> mapOAuth = new HashMap<String, String>();

    private IQHandlerInfo info;

    /**
     * <p>Basic constructor does nothing.</p>
     */
    public IQRegisterHandler() {
        super("XMPP Registration Handler");
        info = new IQHandlerInfo("query", "jabber:iq:register");
    }

    @Override
    public void initialize(XMPPServer server) {
        super.initialize(server);
        userManager = server.getUserManager();
        rosterManager = server.getRosterManager();

        if (probeResult == null) {
            // Create the basic element of the probeResult which contains the basic registration
            // information (e.g. username, passoword and email)
            probeResult = DocumentHelper.createElement(QName.get("query", "jabber:iq:register"));
            probeResult.addElement("username");
            probeResult.addElement("password");
            probeResult.addElement("email");
            probeResult.addElement("name");
            //
            /*
            probeResult.addElement("oauth_version");
            probeResult.addElement("oauth_signature_method");
            probeResult.addElement("oauth_token");
            probeResult.addElement("oauth_token_secret");
            probeResult.addElement("oauth_nonce");
            probeResult.addElement("oauth_timestamp");
            probeResult.addElement("oauth_consumer_key");
            probeResult.addElement("oauth_signature");
            */

            // Create the registration form to include in the probeResult. The form will include
            // the basic information plus name and visibility of name and email.
            // TODO Future versions could allow plugin modules to add new fields to the form
            final DataForm registrationForm = new DataForm(DataForm.Type.form);
            registrationForm.setTitle("XMPP Client Registration");
            registrationForm.addInstruction("Please provide the following information");

            final FormField fieldForm = registrationForm.addField();
            fieldForm.setVariable("FORM_TYPE");
            fieldForm.setType(FormField.Type.hidden);
            fieldForm.addValue("jabber:iq:register");
            if (oAuthEnabled){
                fieldForm.addValue("urn:xmpp:xdata:signature:oauth1");
            }


            final FormField fieldUser = registrationForm.addField();
            fieldUser.setVariable("username");
            fieldUser.setType(FormField.Type.text_single);
            fieldUser.setLabel("Username");
            fieldUser.setRequired(true);

            final FormField fieldName = registrationForm.addField();
            fieldName.setVariable("name");
            fieldName.setType(FormField.Type.text_single);
            fieldName.setLabel("Full name");
            if (UserManager.getUserProvider().isNameRequired()) {
                fieldName.setRequired(true);
            }

            final FormField fieldMail = registrationForm.addField();
            fieldMail.setVariable("email");
            fieldMail.setType(FormField.Type.text_single);
            fieldMail.setLabel("Email");
            if (UserManager.getUserProvider().isEmailRequired()) {
                fieldMail.setRequired(true);
            }

            final FormField fieldPwd = registrationForm.addField();
            fieldPwd.setVariable("password");
            fieldPwd.setType(FormField.Type.text_private);
            fieldPwd.setLabel("Password");
            fieldPwd.setRequired(true);

            /* ########   INICIO    ########## */
            if (isRegisterOAuthEnabled()) {
                // Generate tokens with high entropy tokens
                this.mapOAuth.put("oauth_version", "1.0");
                this.mapOAuth.put("oauth_signature_method","HMAC-SHA256");
                this.mapOAuth.put("oauth_token",StringUtils.hash(UUID.randomUUID().toString(), "SHA-256"));
                this.mapOAuth.put("oauth_token_secret", StringUtils.hash(UUID.randomUUID().toString(), "SHA-256"));
                this.mapOAuth.put("oauth_nonce", StringUtils.hash(UUID.randomUUID().toString(), "SHA-256"));
                this.mapOAuth.put("oauth_timestamp", "" + (new Timestamp(System.currentTimeMillis())).getTime());
                this.mapOAuth.put("oauth_consumer_key", "");
                this.mapOAuth.put("oauth_signature", "");


                final FormField fieldOAuthVersion = registrationForm.addField();
                fieldOAuthVersion.setVariable("oauth_version");
                fieldOAuthVersion.setType(FormField.Type.hidden);
                fieldOAuthVersion.addValue(this.mapOAuth.get("oauth_version"));

                final FormField fieldOAuthSignatureMethod = registrationForm.addField();
                fieldOAuthSignatureMethod.setVariable("oauth_signature_method");
                fieldOAuthSignatureMethod.setType(FormField.Type.hidden);
                fieldOAuthSignatureMethod.addValue(this.mapOAuth.get("oauth_signature_method"));

                final FormField fieldOAuthToken = registrationForm.addField();
                fieldOAuthToken.setVariable("oauth_token");
                fieldOAuthToken.setType(FormField.Type.hidden);
                fieldOAuthToken.setLabel("OAuth Token");
                fieldOAuthToken.addValue(this.mapOAuth.get("oauth_token"));
                fieldOAuthToken.setRequired(true);

                final FormField fieldOAuthSecretToken = registrationForm.addField();
                fieldOAuthSecretToken.setVariable("oauth_token_secret");
                fieldOAuthSecretToken.setType(FormField.Type.hidden);
                fieldOAuthSecretToken.addValue(this.mapOAuth.get("oauth_token_secret"));
                fieldOAuthSecretToken.setRequired(true);

                final FormField fieldOAuthNonce = registrationForm.addField();
                fieldOAuthNonce.setVariable("oauth_nonce");
                fieldOAuthNonce.setType(FormField.Type.hidden);
                fieldOAuthNonce.addValue(this.mapOAuth.get("oauth_nonce"));
                fieldOAuthNonce.setRequired(true);

                final FormField fieldOAuthTimestamp = registrationForm.addField();
                fieldOAuthTimestamp.setVariable("oauth_timestamp");
                fieldOAuthTimestamp.setType(FormField.Type.hidden);
                fieldOAuthTimestamp.addValue(this.mapOAuth.get("oauth_timestamp"));
                fieldOAuthTimestamp.setRequired(true);

                final FormField fieldOAuthConsumerKey = registrationForm.addField();
                fieldOAuthConsumerKey.setVariable("oauth_consumer_key");
                fieldOAuthConsumerKey.setType(FormField.Type.hidden);
                fieldOAuthConsumerKey.setLabel("Consumer Key");
                fieldOAuthConsumerKey.setRequired(true);

                final FormField fieldOAuthSignature = registrationForm.addField();
                fieldOAuthSignature.setVariable("oauth_signature");
                fieldOAuthSignature.setType(FormField.Type.hidden);
                fieldOAuthSignature.setRequired(true);
            }

            // Add the registration form to the probe result.
            probeResult.add(registrationForm.getElement());
        }

        JiveGlobals.migrateProperty("register.inband");
        JiveGlobals.migrateProperty("register.inband.oauth1");
        JiveGlobals.migrateProperty("register.password");

        // See if in-band registration should be enabled (default is true).
        registrationEnabled = JiveGlobals.getBooleanProperty("register.inband", true);
        // registratión using oauth1 as explain xep-0348 be enabled (default is true)
        oAuthEnabled = JiveGlobals.getBooleanProperty("register.inband.oauth1", true);
        // See if users can change their passwords (default is true).
        canChangePassword = JiveGlobals.getBooleanProperty("register.password", true);
    }

    @Override
    public IQ handleIQ(IQ packet) throws PacketException, UnauthorizedException {
        ClientSession session = sessionManager.getSession(packet.getFrom());
        IQ reply = null;
        // If no session was found then answer an error (if possible)
        if (session == null) {
            Log.error("Error during registration. Session not found in " +
                sessionManager.getPreAuthenticatedKeys() +
                " for key " +
                packet.getFrom());
            // This error packet will probably won't make it through
            reply = IQ.createResultIQ(packet);
            reply.setChildElement(packet.getChildElement().createCopy());
            reply.setError(PacketError.Condition.internal_server_error);
            return reply;
        }
        Log.error("######################################################################################");
        if (IQ.Type.get.equals(packet.getType())) {
            this.mapOAuth.put("oauth_version", "1.0");
            this.mapOAuth.put("oauth_signature_method","HMAC-SHA256");
            this.mapOAuth.put("oauth_token",StringUtils.hash(UUID.randomUUID().toString(), "SHA-256"));
            this.mapOAuth.put("oauth_token_secret", StringUtils.hash(UUID.randomUUID().toString(), "SHA-256"));
            this.mapOAuth.put("oauth_nonce", StringUtils.hash(UUID.randomUUID().toString(), "SHA-256"));
            this.mapOAuth.put("oauth_timestamp", "" + (new Timestamp(System.currentTimeMillis())).getTime());
            this.mapOAuth.put("oauth_consumer_key", "");
            this.mapOAuth.put("oauth_signature", "");
            // If inband registration is not allowed, return an error.
            if (!registrationEnabled) {
                reply = IQ.createResultIQ(packet);
                reply.setChildElement(packet.getChildElement().createCopy());
                reply.setError(PacketError.Condition.forbidden);
            }
            else {
                reply = IQ.createResultIQ(packet);
                if (session.getStatus() == Session.STATUS_AUTHENTICATED) {
                    try {
                        User user = userManager.getUser(session.getUsername());
                        Element currentRegistration = probeResult.createCopy();
                        currentRegistration.addElement("registered");
                        currentRegistration.element("username").setText(user.getUsername());
                        currentRegistration.element("password").setText("");
                        currentRegistration.element("email")
                            .setText(user.getEmail() == null ? "" : user.getEmail());
                        currentRegistration.element("name").setText(user.getName());

                        Log.warn("????  Usuario  ????\n\t" + user.toString() + "" +
                            "\n\n #### ProbeResult #### \n" + probeResult.toString() + "" +
                            "\n\n #### CurrentRegistration 1 #### \n" + currentRegistration.getText());

                        Element form = currentRegistration.element(QName.get("x", "jabber:x:data"));
                        Iterator fields = form.elementIterator("field");
                        Element field;
                        while (fields.hasNext()) {
                            field = (Element) fields.next();
                            if ("username".equals(field.attributeValue("var"))) {
                                field.addElement("value").addText(user.getUsername());
                            }
                            else if ("name".equals(field.attributeValue("var"))) {
                                field.addElement("value").addText(user.getName());
                            }
                            else if ("email".equals(field.attributeValue("var"))) {
                                field.addElement("value")
                                    .addText(user.getEmail() == null ? "" : user.getEmail());
                            }
                        }

                        reply.setChildElement(currentRegistration);

                    }
                    catch (UserNotFoundException e) {
                        reply.setChildElement(probeResult.createCopy());
                    }
                }
                else {
                    // This is a workaround. Since we don't want to have an incorrect TO attribute
                    // value we need to clean up the TO attribute. The TO attribute will contain an
                    // incorrect value since we are setting a fake JID until the user actually
                    // authenticates with the server.

                    reply.setTo((JID) null);
                    //reply.setChildElement(probeResult.createCopy());
                    reply.setChildElement(tanteo().createCopy());

                }
            }
        }
        else if (IQ.Type.set.equals(packet.getType())) {
            try {
                Element iqElement = packet.getChildElement();
                Log.warn("Impresion linea " + Thread.currentThread().getStackTrace()[2].getLineNumber() + ".  Dentro del SET Abajo del primer try.");
                if (iqElement.element("remove") != null) {
                    Log.warn("Impresion linea " + Thread.currentThread().getStackTrace()[2].getLineNumber() + ".  Entre al irf(iqElement.element(\"remove\") != null) ");
                    // If inband registration is not allowed, return an error.
                    if (!registrationEnabled) {
                        reply = IQ.createResultIQ(packet);
                        reply.setChildElement(packet.getChildElement().createCopy());
                        reply.setError(PacketError.Condition.forbidden);
                    }
                    else {
                        Log.warn("Impresion linea " + Thread.currentThread().getStackTrace()[2].getLineNumber() + ".  Entre al else del if(!registrationEnabled) ) ");
                        if (session.getStatus() == Session.STATUS_AUTHENTICATED) {
                            User user = userManager.getUser(session.getUsername());
                            // Delete the user
                            userManager.deleteUser(user);
                            // Delete the roster of the user
                            rosterManager.deleteRoster(session.getAddress());
                            // Delete the user from all the Groups
                            GroupManager.getInstance().deleteUser(user);

                            reply = IQ.createResultIQ(packet);
                            session.process(reply);
                            // Take a quick nap so that the client can process the result
                            Thread.sleep(10);
                            // Close the user's connection
                            final StreamError error = new StreamError(StreamError.Condition.not_authorized);
                            for (ClientSession sess : sessionManager.getSessions(user.getUsername()) )
                            {
                                sess.deliverRawText(error.toXML());
                                sess.close();
                            }
                            // The reply has been sent so clean up the variable
                            reply = null;
                        }
                        else {
                            throw new UnauthorizedException();
                        }
                    }
                }
                else {
                    Log.warn("Impresion linea 1");

                    String username;
                    String password = null;
                    String email = null;
                    String name = null;

                    User newUser = null;
                    DataForm registrationForm;
                    FormField field;

                    Element formElement = iqElement.element("x");
                    // Check if a form was used to provide the registration info
                    if (formElement != null) {
                        Log.warn("Impresion linea 2");
                        // Get the sent form
                        registrationForm = new DataForm(formElement);
                        // Get the username sent in the form
                        List<String> values = registrationForm.getField("username").getValues();
                        Map<String, String> valores = new HashMap<String, String>();


                        Log.warn("Impresion linea 3");
                        // Get the username sent in the forms
                        username = (!values.isEmpty() ? values.get(0) : " ");
                        Log.warn("El usuario que llego es: \"" + username +"\"");
                        this.mapOAuth.put("username", username);
                        valores.put("username", username);

                        Log.warn("Impresion linea 4");
                        // Get the password sent in the forms
                        field = registrationForm.getField("password");
                        if (field != null) {
                            values = field.getValues();
                            password = (!values.isEmpty() ? values.get(0) : " ");
                            valores.put("password", password);
                            this.mapOAuth.put("password", password);
                        }

                        Log.warn("Impresion linea 5");
                        // Get the email sent in the form
                        field = registrationForm.getField("email");
                        if (field != null) {
                            values = field.getValues();
                            email = (!values.isEmpty() ? values.get(0) : " ");
                            valores.put("email", email);
                            this.mapOAuth.put("email", email);
                        }

                        Log.warn("Impresion linea 6");
                        // Get the name sent in the form
                        field = registrationForm.getField("name");
                        if (field != null) {
                            values = field.getValues();
                            name = (!values.isEmpty() ? values.get(0) : " ");
                            valores.put("name", name);
                            this.mapOAuth.put("name", name);
                        }
                        Log.warn("Impresion linea 7" + Thread.currentThread().getStackTrace()[2].getLineNumber() + ". El valor de isRegisterOAuthEnabled() es \": " + isRegisterOAuthEnabled() + "\"");
                        if (isRegisterOAuthEnabled()) {
                            field = registrationForm.getField("oauth_version");
                            if (field != null){
                                values = field.getValues();
                                valores.put("oauth_version", (!values.isEmpty() ? values.get(0) : ""));
                            }
                            field = registrationForm.getField("oauth_signature_method");
                            if (field != null){
                                values = field.getValues();

                                valores.put("oauth_signature_method", (!values.isEmpty() ? values.get(0) : ""));
                            }
                            field = registrationForm.getField("oauth_token");
                            if (field != null){
                                values = field.getValues();
                                valores.put("oauth_token", (!values.isEmpty() ? values.get(0) : ""));
                            }
                            field = registrationForm.getField("oauth_token_secret");
                            if (field != null){
                                values = field.getValues();
                                valores.put("oauth_token_secret", (!values.isEmpty() ? values.get(0) : ""));
                            }
                            field = registrationForm.getField("oauth_nonce");
                            if (field != null){
                                values = field.getValues();
                                valores.put("oauth_nonce", (!values.isEmpty() ? values.get(0) : ""));
                            }
                            field = registrationForm.getField("oauth_timestamp");
                            if (field != null){
                                values = field.getValues();
                                valores.put("oauth_timestamp", (!values.isEmpty() ? values.get(0) : ""));
                            }
                            field = registrationForm.getField("oauth_consumer_key");
                            if (field != null){
                                values = field.getValues();
                                valores.put("oauth_consumer_key", (!values.isEmpty() ? values.get(0) : ""));
                                this.mapOAuth.put("oauth_consumer_key", (!values.isEmpty() ? values.get(0) : ""));
                            }
                            field = registrationForm.getField("oauth_signature");
                            if (field != null){
                                values = field.getValues();
                                valores.put("oauth_signature", (!values.isEmpty() ? values.get(0) : ""));
                                this.mapOAuth.put("oauth_signature", (!values.isEmpty() ? values.get(0) : ""));
                            }


                            Log.warn("### IMPRESION DE mapOAuth ###");
                            for (Map.Entry entry : mapOAuth.entrySet()){
                                Log.warn("\t" + entry.getKey() + ": " +  entry.getValue());
                            }

                            Log.warn("### IMPRESION DE map Valores ###");
                            for (Map.Entry entry : valores.entrySet()){
                                Log.warn("\t" + entry.getKey() + ": " +  entry.getValue());
                            }



                            // Aseguramos que los valores que enviamos sean los mismos que llegan
                            // y que los campos consumerKey y Signature contengan data
                            if (this.mapOAuth.get("oauth_version").equals(valores.get("oauth_version"))  &&
                                this.mapOAuth.get("oauth_signature_method").equals(valores.get("oauth_signature_method")) &&
                                this.mapOAuth.get("oauth_token").equals(valores.get("oauth_token")) &&
                                this.mapOAuth.get("oauth_token_secret").equals(valores.get("oauth_token_secret")) &&
                                this.mapOAuth.get("oauth_nonce").equals(valores.get("oauth_nonce")) &&
                                this.mapOAuth.get("oauth_timestamp").equals(valores.get("oauth_timestamp")) &&
                                valores.get("oauth_consumer_key").trim() != "" &&
                                valores.get("oauth_signature").trim() != "")
                            {
                                Log.warn("%%%%%%%%%%%%%% ENTRÉ en el IF condición %%%%%%%%%%%");
                                this.consumerData = checkOAuthConsumer(valores.get("oauth_consumer_key"));
                                // Si el consumerKey proporcionado por el cliente no esta en nuestros registros
                                if (this.consumerData == null){
                                    Log.error("No se ha encontrado consumerKey");
                                    throw new UnauthorizedException();
                                }
                                else {
                                    this.oAuthConsumerSecret = this.consumerData[1];

                                    if (!calculateSignature(new TreeMap<String, String>(mapOAuth), packet.getFrom().toString().trim()).equals(valores.get("oauth_signature").trim())
                                        || Integer.parseInt(this.consumerData[1]) == Integer.parseInt(this.consumerData[2])){
                                        Log.warn("\n\nError al registrar NUEVA cuenta:\n\tConsumer Secret: " + this.consumerData[0] + "\n\tamountOfIdentities: " + this.consumerData[1] + "\n\tidentitiesCreates: " + this.consumerData[3]);
                                        throw new UnauthorizedException();
                                    }
                                }
                            }
                            else{
                                Log.warn("%%%%%%%%%%%%%% ENTRÉ en en ELSE condición %%%%%%%%%%%");
                                Log.warn("Value empty(ies) or null(s)\n\n" + packet.toString());
                                throw new UnauthorizedException();
                            }

                        }
                        Log.warn("Impresion linea 8");
                    }
                    else {
                        Log.warn("Impresion linea 9");
                        // Get the registration info from the query elements
                        username = iqElement.elementText("username");
                        password = iqElement.elementText("password");
                        email = iqElement.elementText("email");
                        name = iqElement.elementText("name");
                    }
                    if (email != null && email.matches("\\s*")) {
                        email = null;
                    }
                    if (name != null && name.matches("\\s*")) {
                        name = null;
                    }

                    // So that we can set a more informative error message back, lets test this for
                    // stringprep validity now.
                    if (username != null) {
                        Stringprep.nodeprep(username);
                    }

                    if (session.getStatus() == Session.STATUS_AUTHENTICATED) {
                        // Flag that indicates if the user is *only* changing his password
                        boolean onlyPassword = false;
                        if (iqElement.elements().size() == 2 &&
                            iqElement.element("username") != null &&
                            iqElement.element("password") != null) {
                            onlyPassword = true;
                        }
                        // If users are not allowed to change their password, return an error.
                        if (password != null && !canChangePassword) {
                            reply = IQ.createResultIQ(packet);
                            reply.setChildElement(packet.getChildElement().createCopy());
                            reply.setError(PacketError.Condition.forbidden);
                            return reply;
                        }
                        // If inband registration is not allowed, return an error.
                        else if (!onlyPassword && !registrationEnabled) {
                            reply = IQ.createResultIQ(packet);
                            reply.setChildElement(packet.getChildElement().createCopy());
                            reply.setError(PacketError.Condition.forbidden);
                            return reply;
                        }
                        else {
                            User user = userManager.getUser(session.getUsername());
                            if (user.getUsername().equalsIgnoreCase(username)) {
                                if (password != null && password.trim().length() > 0) {
                                    user.setPassword(password);
                                }
                                if (!onlyPassword) {
                                    user.setEmail(email);
                                }
                                newUser = user;
                            }
                            else if (password != null && password.trim().length() > 0) {
                                // An admin can create new accounts when logged in.
                                newUser = userManager.createUser(username, password, null, email);
                            }
                            else {
                                // Deny registration of users with no password
                                reply = IQ.createResultIQ(packet);
                                reply.setChildElement(packet.getChildElement().createCopy());
                                reply.setError(PacketError.Condition.not_acceptable);
                                return reply;
                            }
                        }
                    }
                    else {
                        // If inband registration is not allowed, return an error.
                        if (!registrationEnabled) {
                            reply = IQ.createResultIQ(packet);
                            reply.setChildElement(packet.getChildElement().createCopy());
                            reply.setError(PacketError.Condition.forbidden);
                            return reply;
                        }
                        // Inform the entity of failed registration if some required
                        // information was not provided
                        else if (password == null || password.trim().length() == 0) {
                            reply = IQ.createResultIQ(packet);
                            reply.setChildElement(packet.getChildElement().createCopy());
                            reply.setError(PacketError.Condition.not_acceptable);
                            return reply;
                        }
                        else {
                            // Create the new account

                            if (oAuthEnabled){
                                if (this.updateConsumerIdentities(1 + Integer.parseInt(this.consumerData[2]))){
                                    // TODO: ESTA PASANDO HASTA AQUI, CUANDO NO DEBIESE LLEGAR PORQUE NO LE ENTREGO KEY NI FIRMAial
                                    newUser = userManager.createUser(username, password, name, email);
                                }
                            } else {
                                newUser = userManager.createUser(username, password, name, email);
                            }


                        }
                    }
                    // Set and save the extra user info (e.g. full name, etc.)
                    if (newUser != null && name != null && !name.equals(newUser.getName())) {
                        newUser.setName(name);
                    }

                    reply = IQ.createResultIQ(packet);
                }
            }
            catch (UnauthorizedException e){
                reply = IQ.createResultIQ(packet);
                reply.setChildElement(packet.getChildElement().createCopy());
                reply.setError(PacketError.Condition.not_authorized);
            }
            catch (UserAlreadyExistsException e) {
                reply = IQ.createResultIQ(packet);
                reply.setChildElement(packet.getChildElement().createCopy());
                reply.setError(PacketError.Condition.conflict);
            }
            catch (UserNotFoundException e) {
                reply = IQ.createResultIQ(packet);
                reply.setChildElement(packet.getChildElement().createCopy());
                reply.setError(PacketError.Condition.bad_request);
            }
            catch (StringprepException e) {
                // The specified username is not correct according to the stringprep specs
                reply = IQ.createResultIQ(packet);
                reply.setChildElement(packet.getChildElement().createCopy());
                reply.setError(PacketError.Condition.jid_malformed);
            }
            catch (IllegalArgumentException e) {
                // At least one of the fields passed in is not valid
                reply = IQ.createResultIQ(packet);
                reply.setChildElement(packet.getChildElement().createCopy());
                reply.setError(PacketError.Condition.not_acceptable);
                Log.warn(e.getMessage(), e);
            }
            catch (UnsupportedOperationException e) {
                // The User provider is read-only so this operation is not allowed
                reply = IQ.createResultIQ(packet);
                reply.setChildElement(packet.getChildElement().createCopy());
                reply.setError(PacketError.Condition.not_allowed);
            }
            catch (Exception e) {
                // Some unexpected error happened so return an internal_server_error
                reply = IQ.createResultIQ(packet);
                reply.setChildElement(packet.getChildElement().createCopy());
                reply.setError(PacketError.Condition.internal_server_error);
                Log.error(e.getMessage(), e);
            }
        }
        if (reply != null) {
            // why is this done here instead of letting the iq handler do it?
            session.process(reply);
        }
        return null;
    }

    public boolean isRegisterOAuthEnabled(){
        return oAuthEnabled;
    }

    public void setRegisterOAuthEnabled(boolean allowed){
        oAuthEnabled = allowed;
        JiveGlobals.setProperty("rregister.inband.oauth1", oAuthEnabled ? "true" : "false");
        Log.warn("Se ha modificado oAuthEnabled a: " + oAuthEnabled);
    }

    public boolean isInbandRegEnabled()
    {
        return registrationEnabled && !UserManager.getUserProvider().isReadOnly();
    }

    public void setInbandRegEnabled(boolean allowed)
    {
        if ( allowed && UserManager.getUserProvider().isReadOnly() )
        {
            Log.warn( "Enabling in-band registration has no effect, as the user provider for this system is read-only." );
        }
        registrationEnabled = allowed;
        JiveGlobals.setProperty("register.inband", registrationEnabled ? "true" : "false");
    }

    public boolean canChangePassword()
    {
        return canChangePassword && !UserManager.getUserProvider().isReadOnly();
    }

    public void setCanChangePassword(boolean allowed)
    {
        if ( allowed && UserManager.getUserProvider().isReadOnly() )
        {
            Log.warn( "Allowing password changes has no effect, as the user provider for this system is read-only." );
        }
        canChangePassword = allowed;
        JiveGlobals.setProperty("register.password", canChangePassword ? "true" : "false");
    }

    public String calculateSignature(Map <String, String> sortOAuthValues, String clientJID) throws UnsupportedEncodingException, UserNotFoundException {
        String PStr = "";
        String BStr = "";
        String hash;

        /* DEBUG Values
        ******************/
        String debugString = "";
        Log.error("**********************************************************************************************************" +
            "\nDentro del metodo");
        /****************/

        for (Map.Entry<String, String> entry : sortOAuthValues.entrySet()) {
            debugString += "\n\t\t" + entry.getKey() + ": \"" + entry.getValue().trim() + "\"";
            PStr += entry.getKey() + "=" + entry.getValue() + "&";
        }

        BStr = "submit&" + clientJID + "&" + PStr;

        byte[] hexKey = (this.oAuthConsumerSecret + "&" + sortOAuthValues.get("oauth_token_secret").toString()).getBytes("US-ASCII");

        try {
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(hexKey, "HmacSHA256"); //Primer p
            sha256_HMAC.init(secret_key);

            hash = Base64.encodeBase64String(sha256_HMAC.doFinal(BStr.getBytes("US-ASCII")));
            System.out.println(hash);
            Log.warn("\n"+ debugString +"\n\t - HashRecibido - \n\t\tHashRecibido: " + hash + "\n");
        }
        catch (Exception e){
            Log.error("\n" + e.toString() + "\n");
            throw new IllegalArgumentException();
        }

        if (hash.length() == 0)
            throw new UserNotFoundException();
        Log.error("******************************************************************************************");
        return hash.toString();
    }

    // Comprueba si el 'secret' del consumer corresponde al ingresado
    public String[] checkOAuthConsumer(String oAuthConsumerSecret) {
        String[] result = null;
        String JDBC_SELECT = "SELECT consumerSecret, amountOfIdentities, identitiesCreates  from ofOAuth where consumerKey = ?";

        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            con = DbConnectionManager.getConnection();
            pstmt = con.prepareStatement(JDBC_SELECT);
            rs = pstmt.executeQuery();

            if (rs.next()){
                rs.beforeFirst();
                while (rs.next()){
                    result = new String[] {
                        rs.getString("consumerSecret"),
                        rs.getString("amountOfIdentities"),
                        rs.getString("identitiesCreates") };
                }
            }
            else {
                result = null;
            }
        } catch (SQLException e) {
            Log.error(e.getMessage(), e);
        }
        catch (NumberFormatException e) {
            Log.error(e.getMessage(), e);
        } finally {
            DbConnectionManager.closeConnection(rs, pstmt, con);
        }
        return result;
    }

    public boolean updateConsumerIdentities(int amountIdentiesCreated) {
        boolean exito = false;
        String JDBC_UPDATE = "UPDATE Customers SET amountOfIdentities = ? WHERE CustomerID = ?";
        Connection con = null;
        PreparedStatement pstmt = null;

        try {
            con = DbConnectionManager.getConnection();
            pstmt = con.prepareStatement(JDBC_UPDATE);
            pstmt.setInt(1, amountIdentiesCreated);
            pstmt.setString(2,this.mapOAuth.get("oauth_consumer_key"));

            pstmt.executeUpdate();
            exito = true;
        } catch (SQLException e) {
            Log.error(e.getMessage(), e);
        }
        catch (NumberFormatException e) {
            Log.error(e.getMessage(), e);
        } finally {
            DbConnectionManager.closeConnection(pstmt, con);
        }
        return exito;
    }

    public boolean insertConsumer(String newConsumeKey, String newConsumerSecret, int autorizedCreations) {
        boolean exito = false;
        String JDBC_UPDATE = "INSERT INTO ofOAuth (consumerKey, consumerSecret, amountOfIdentities, identitiesCreates) " +
            "values (?, ?, ?, ?)";

        String hashConsumerSecret = StringUtils.hash(newConsumerSecret, "SHA-256");

        Connection con = null;
        PreparedStatement pstmt = null;

        try {
            con = DbConnectionManager.getConnection();
            pstmt = con.prepareStatement(JDBC_UPDATE);
            pstmt.setString(1, newConsumeKey);
            pstmt.setString(2,hashConsumerSecret);
            pstmt.setInt(3, autorizedCreations);
            pstmt.setInt(4,0);
            pstmt.execute();
            exito = true;
        } catch (SQLException e) {
            Log.error(e.getMessage(), e);
        }
        catch (NumberFormatException e) {
            Log.error(e.getMessage(), e);
        } finally {
            DbConnectionManager.closeConnection(pstmt, con);
        }
        return exito;
    }

    public ArrayList<ArrayList <String>> getConsumers() {
        ArrayList<ArrayList <String>> table = new ArrayList<ArrayList<String>>();
        ArrayList<String> row;
        String JDBC_SELECT = "SELECT * FROM ofOAuth";
        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            con = DbConnectionManager.getConnection();
            pstmt = con.prepareStatement(JDBC_SELECT);
            rs = pstmt.executeQuery();
            if (rs.next()){
                rs.beforeFirst();
                while (rs.next()){
                    row = new ArrayList<String>();
                    row.add(rs.getString("consumerKey"));
                    row.add("**********");
                    row.add(rs.getString("amountOfIdentities"));
                    row.add(rs.getString("identitiesCreates"));
                    table.add(row);
                }
            }

        } catch (SQLException e) {
            table = null;
            Log.error(e.getMessage(), e);
        }
        catch (NumberFormatException e) {
            table = null;
            Log.error(e.getMessage(), e);
        } finally {
            DbConnectionManager.closeConnection(rs, pstmt, con);
        }
        return table;
    }


    public Element tanteo(){
        //Elemento principal
        Element RegistryStanza = DocumentHelper.createElement(QName.get("query", "jabber:iq:register"));

        // Se crea el nodo <x xmlns='jabber:x:data' type='form'>
        DataForm registrationForm = new DataForm(DataForm.Type.form);
        registrationForm.setTitle("XMPP Client Registration");
        registrationForm.addInstruction("Please provide the following information");

        FormField fieldForm = registrationForm.addField();
        fieldForm.setVariable("FORM_TYPE");
        fieldForm.setType(FormField.Type.hidden);
        fieldForm.addValue("jabber:iq:register");
        if (isRegisterOAuthEnabled()){
            fieldForm.addValue("urn:xmpp:xdata:signature:oauth1");
        }


        FormField fieldUser = registrationForm.addField();
        fieldUser.setVariable("username");
        fieldUser.setType(FormField.Type.text_single);
        fieldUser.setLabel("Username");
        fieldUser.setRequired(true);

        FormField fieldName = registrationForm.addField();
        fieldName.setVariable("name");
        fieldName.setType(FormField.Type.text_single);
        fieldName.setLabel("Full name");
        if (UserManager.getUserProvider().isNameRequired()) {
            fieldName.setRequired(true);
        }

        FormField fieldMail = registrationForm.addField();
        fieldMail.setVariable("email");
        fieldMail.setType(FormField.Type.text_single);
        fieldMail.setLabel("Email");
        if (UserManager.getUserProvider().isEmailRequired()) {
            fieldMail.setRequired(true);
        }

        FormField fieldPwd = registrationForm.addField();
        fieldPwd.setVariable("password");
        fieldPwd.setType(FormField.Type.text_private);
        fieldPwd.setLabel("Password");
        fieldPwd.setRequired(true);

        if (isRegisterOAuthEnabled()){
            // Generate tokens with high entropy tokens
            this.mapOAuth.put("oauth_version", "1.0");
            this.mapOAuth.put("oauth_signature_method","HMAC-SHA256");
            this.mapOAuth.put("oauth_token",StringUtils.hash(UUID.randomUUID().toString(), "SHA-256"));
            this.mapOAuth.put("oauth_token_secret", StringUtils.hash(UUID.randomUUID().toString(), "SHA-256"));
            this.mapOAuth.put("oauth_nonce", StringUtils.hash(UUID.randomUUID().toString(), "SHA-256"));
            this.mapOAuth.put("oauth_timestamp", "" + (new Timestamp(System.currentTimeMillis())).getTime());
            this.mapOAuth.put("oauth_consumer_key", "");
            this.mapOAuth.put("oauth_signature", "");


            final FormField fieldOAuthVersion = registrationForm.addField();
            fieldOAuthVersion.setVariable("oauth_version");
            fieldOAuthVersion.setType(FormField.Type.hidden);
            fieldOAuthVersion.addValue(this.mapOAuth.get("oauth_version"));

            final FormField fieldOAuthSignatureMethod = registrationForm.addField();
            fieldOAuthSignatureMethod.setVariable("oauth_signature_method");
            fieldOAuthSignatureMethod.setType(FormField.Type.hidden);
            fieldOAuthSignatureMethod.addValue(this.mapOAuth.get("oauth_signature_method"));

            final FormField fieldOAuthToken = registrationForm.addField();
            fieldOAuthToken.setVariable("oauth_token");
            fieldOAuthToken.setType(FormField.Type.hidden);
            fieldOAuthToken.setLabel("OAuth Token");
            fieldOAuthToken.addValue(this.mapOAuth.get("oauth_token"));
            fieldOAuthToken.setRequired(true);

            final FormField fieldOAuthSecretToken = registrationForm.addField();
            fieldOAuthSecretToken.setVariable("oauth_token_secret");
            fieldOAuthSecretToken.setType(FormField.Type.hidden);
            fieldOAuthSecretToken.addValue(this.mapOAuth.get("oauth_token_secret"));
            fieldOAuthSecretToken.setRequired(true);

            final FormField fieldOAuthNonce = registrationForm.addField();
            fieldOAuthNonce.setVariable("oauth_nonce");
            fieldOAuthNonce.setType(FormField.Type.hidden);
            fieldOAuthNonce.addValue(this.mapOAuth.get("oauth_nonce"));
            fieldOAuthNonce.setRequired(true);

            final FormField fieldOAuthTimestamp = registrationForm.addField();
            fieldOAuthTimestamp.setVariable("oauth_timestamp");
            fieldOAuthTimestamp.setType(FormField.Type.hidden);
            fieldOAuthTimestamp.addValue(this.mapOAuth.get("oauth_timestamp"));
            fieldOAuthTimestamp.setRequired(true);

            final FormField fieldOAuthConsumerKey = registrationForm.addField();
            fieldOAuthConsumerKey.setVariable("oauth_consumer_key");
            fieldOAuthConsumerKey.setType(FormField.Type.hidden);
            fieldOAuthConsumerKey.setLabel("Consumer Key");
            fieldOAuthConsumerKey.setRequired(true);

            final FormField fieldOAuthSignature = registrationForm.addField();
            fieldOAuthSignature.setVariable("oauth_signature");
            fieldOAuthSignature.setType(FormField.Type.hidden);
            fieldOAuthSignature.setRequired(true);
        }

        RegistryStanza.add(registrationForm.getElement());
        return RegistryStanza;
    }



    @Override
    public IQHandlerInfo getInfo() {
        return info;
    }

    @Override
    public Iterator<String> getFeatures() {
        int i = 0;
        List<String> iQRegfeatureList = new ArrayList<String>();
        iQRegfeatureList.add("jabber:iq:register");
        iQRegfeatureList.add("urn:xmpp:xdata:signature:oauth1");

        return iQRegfeatureList.iterator();
        //return Collections.singleton("jabber:iq:register").iterator();
    }



}
