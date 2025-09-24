package com.example.springboot2.controller;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.authn.AuthnRequest;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.util.Util;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Controller
@RequestMapping("/sso/*")
public class SAMLRequestServlet {

    @Value("classpath:sso/private-test.key")
    private Resource udemyPrivateKey;

    /** ktedu > login.do 에 추가
     * udemy 에서 ktedu.com 으로 SSO 로그인 요청
     * /sso/login/udemy 로 접속
     *  >> ktedu 에 로그인이 되어 있다면 -> 해당 로직 실행
     *  >> ktedu 에 로그인이 안되어 있다면 -> 로그인 이후 해당 로직 실행
     * */
    @RequestMapping(value = "/login/{channel}", method = { RequestMethod.GET })
    public void ssoLogin(HttpServletRequest request, HttpServletResponse response, @PathVariable String channel) throws Exception {
        // SAML 설정 로드
        Auth auth = new Auth(request, response);
        AuthnRequest authnRequest = new AuthnRequest(auth.getSettings());

        // replay attack 방지
        if(auth.getLastRequestId() != null && auth.getLastRequestId().equals(authnRequest.getId())) {
            return;
        }

        Saml2Settings settings = auth.getSettings();

        // 사용자 정보 설정 TODO > 실제 접속자로 변경해야 함
        Map<String, String> userData = new HashMap<>();
        userData.put("email", "youngjip.yoon@kt.com");
        userData.put("channel", channel);

        // request id 값
//        userData.put("requestId", authnRequest.getId());
        userData.put("requestId", null);

        // session id 깂
        String sessionIdx = "KT_" + UUID.randomUUID();
        userData.put("sessionIdx", sessionIdx);
        request.getSession().setAttribute("sessionIdx", sessionIdx);

        // relay state 값
        String relayState =  request.getParameter("RelayState");
//        String relayUrl = "https://pingone.com/1.0/d905a6ca-adf9-45e2-9b9d-0d6485f27206";

        // SAML Response 생성
        String samlResponseXml = createSamlResponse(settings, userData);

        // Base64 인코딩
        String encodedResponse = Base64.getEncoder().encodeToString(samlResponseXml.getBytes());

        // HTML Form 전송
        String htmlForm = "<form method='POST' action='" + settings.getSpAssertionConsumerServiceUrl() + "'>" +
                "<input type='hidden' name='SAMLResponse' value='" + encodedResponse + "'/>" +
                "<input type='hidden' name='RelayState' value='" + relayState + "'/>" +
                "<input type='submit' value='Continue'/>" +
                "</form>" +
                "<script>document.forms[0].submit();</script>";

        response.setContentType("text/html");
        response.getWriter().write(htmlForm);
    }

    // saml response 생성
    public String createSamlResponse(Saml2Settings settings, Map<String, String> userData) throws Exception {
        String userEmail = userData.get("email");
        String channel = userData.get("channel");

        String formattedTime = getNowDateTime(true, null);
        String notOnOrAfterTime = getNowDateTime(true, 10L);    // 인증서 유효시간 : 10분 (보통 5~10분)
        String notBefore = getNowDateTime(true, -10L);

        String idKey = "KT_";
        String responseId = idKey + UUID.randomUUID();
        String assertionId = idKey + UUID.randomUUID();
        String sessionIdx = userData.get("sessionIdx");

        // SP 에서 보낸 AuthnRequest 의 ID
        String inResponseId = userData.get("requestId");

        String idpEntityId = settings.getIdpEntityId();
        String spEntityId = settings.getSpEntityId();
        String spUrl = settings.getSpAssertionConsumerServiceUrl().toString();

        // cert, private key
        X509Certificate cert = settings.getIdpx509cert();
        PrivateKey privateKey = getPrivateKey(channel);

        String signAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        String digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

        // assertion xml
        String assertionXml =
                "    <saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"" +
                        " ID=\"" + assertionId + "\"" +
                        " IssueInstant=\"" + formattedTime + "\"" +
                        " Version=\"2.0\"" +
                        (inResponseId != null ? " InResponseTo=\"" + inResponseId + "\"" : "") +
                        " >\n" +
                        "        <saml:Issuer>" + idpEntityId + "</saml:Issuer>\n" +
                // <!-- Assertion 유효성 조건 -->
                "        <saml:Conditions NotBefore=\"" + notBefore + "\" NotOnOrAfter=\"" + notOnOrAfterTime + "\">\n" +
                "            <saml:AudienceRestriction>\n" +
                "                <saml:Audience>" + spEntityId + "</saml:Audience>\n" +
                "            </saml:AudienceRestriction>\n" +
                "        </saml:Conditions>\n" +
                // <!-- Subject (사용자 정보) -->
                "        <saml:Subject>\n" +
                "            <saml:NameID SPNameQualifier=\"" + spEntityId + "\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified\">" +
                                userEmail +
                            "</saml:NameID>\n" +
                "            <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n" +
                "                <saml:SubjectConfirmationData NotOnOrAfter=\"" + notOnOrAfterTime + "\" Recipient=\"" + spUrl + "\"" +
                                (inResponseId != null ? " InResponseTo=\"" + inResponseId + "\"" : "") + "/>\n" +
                "            </saml:SubjectConfirmation>\n" +
                "        </saml:Subject>\n" +
                // <!-- 사용자 인증 정보 -->
                "        <saml:AuthnStatement AuthnInstant=\"" + formattedTime + "\" SessionNotOnOrAfter=\"" + notOnOrAfterTime + "\" SessionIndex=\"" + sessionIdx + "\">\n" +
                "            <saml:AuthnContext>\n" +
                "                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>\n" +
                "            </saml:AuthnContext>\n" +
                "        </saml:AuthnStatement>\n" +
                // <!-- 추가 속성 -->
                "       <saml:AttributeStatement>\n" +
                "            <saml:Attribute Name='email' Format='urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified'>\n" +   //
                "                <saml:AttributeValue>" + userEmail + "</saml:AttributeValue>\n" +
                "            </saml:Attribute>\n" +
                "        </saml:AttributeStatement>\n" +
                "    </saml:Assertion>\n";

        // assertion signed
        Document assertion = Util.loadXML(assertionXml);
        String signedAssertion = Util.addSign(assertion, privateKey, cert, signAlgorithm, digestAlgorithm);

        // saml response
        String responseXml =
                "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
                "ID=\"" + responseId + "\" " +
                "Version=\"2.0\" " +
                "IssueInstant=\"" + formattedTime + "\" " +
                "Destination=\"" + spUrl + "\">\n" +
                // Issuer (IDP)
                "    <saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + idpEntityId + "</saml:Issuer>\n" +
                "    <samlp:Status>\n" +
                "        <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n" +
                "    </samlp:Status>\n" +
                // Assertion
                signedAssertion +
                "</samlp:Response>";

        // response signed
        Document response = Util.loadXML(responseXml);
        return Util.addSign(response, privateKey, cert, signAlgorithm, digestAlgorithm);
    }

    /** logout TODO 더 테스트 필요 */
    @RequestMapping(value = "/logout/{channel}", method = { RequestMethod.GET })
    public void ssoLogoutTemp(HttpServletRequest request, HttpServletResponse response, @PathVariable String channel) throws Exception {

    }

    /** logout TODO 더 테스트 필요 */
    public void ssoLogout(HttpServletRequest request, HttpServletResponse response, @PathVariable String channel) throws Exception {
        Auth auth = new Auth(request, response);
        Saml2Settings settings = auth.getSettings();

        String formattedTime = getNowDateTime(true, null);

        String idKey = "KT_";
        String requestId = idKey + UUID.randomUUID();
        String sessionIdx = request.getSession().getAttribute("sessionIdx") != null ? request.getSession().getAttribute("sessionIdx").toString() : null;

        String idpEntityId = settings.getIdpEntityId();
        String spEntityId = settings.getSpEntityId();
        String spSLOUrl = settings.getSpSingleLogoutServiceUrl().toString();

        // cert, private key
        X509Certificate cert = settings.getIdpx509cert();
        PrivateKey privateKey = getPrivateKey(channel);

        String signAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        String digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

//        String relayState =  request.getParameter("RelayState");
//        String relayState = "https://ktedu.kt.com";
        String relayUrl = "https://pingone.com/1.0/d905a6ca-adf9-45e2-9b9d-0d6485f27206";

        String logoutXml =
                "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"" +
                        " ID=\"" + requestId + "\"" +
                        " Version=\"2.0\"" +
                        " IssueInstant=\"" + formattedTime + "\"" +
                        " Destination=\"" + spSLOUrl + "\">\n" +
                "  <saml:Issuer>" + idpEntityId + "</saml:Issuer>\n" +
                "  <saml:NameID SPNameQualifier=\"" + spEntityId + "\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">" + sessionIdx + "</saml:NameID>\n" +
                "</samlp:LogoutRequest>";

        Document logout = Util.loadXML(logoutXml);
        String logoutRequest = Util.addSign(logout, privateKey, cert, signAlgorithm, digestAlgorithm);

        // Base64 인코딩
        String encodedRequest = Base64.getEncoder().encodeToString(logoutRequest.getBytes());

        // HTML Form 전송
        String htmlForm = "<form method='POST' action='" + spSLOUrl + "'>" +
                "<input type='hidden' name='SAMLRequest' value='" + encodedRequest + "'/>" +
                "<input type='hidden' name='RelayState' value='" + relayUrl + "'/>" +
                "<input type='submit' value='Continue'/>" +
                "</form>" +
                "<script>document.forms[0].submit();</script>";

        response.setContentType("text/html");
        response.getWriter().write(htmlForm);
    }

    /** idp metadata 생성 */
    @RequestMapping("/metadata/{channel}")
    public void getMetadata(HttpServletRequest request, HttpServletResponse response, @PathVariable String channel, Boolean downloadFlag) throws Exception {
        try {
            Auth auth = new Auth(request, response);
            Saml2Settings settings = auth.getSettings();

            String idpEntityId = settings.getIdpEntityId();
            String idpCert = getBase64Cert(settings.getIdpx509cert().getEncoded(), true);
            String idpSSOServiceUrl = escapeXml(settings.getIdpSingleSignOnServiceUrl());
            String idpLogoutUrl = escapeXml(settings.getIdpSingleLogoutServiceUrl()) ;

            String idpMetadata =
                    "<md:EntityDescriptor entityID=\"" + idpEntityId + "\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">\n" +
                    "    <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
                    "        <md:KeyDescriptor use=\"signing\">\n" +
                    "            <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                    "                <ds:X509Data>\n" +
                    "                    <ds:X509Certificate>\n" +
                                             idpCert +
                    "                    </ds:X509Certificate>\n" +
                    "                </ds:X509Data>\n" +
                    "            </ds:KeyInfo>\n" +
                    "        </md:KeyDescriptor>\n" +
                    "        <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"" + idpSSOServiceUrl + "\"/>\n" +
                    "        <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"" + idpLogoutUrl + "\"/>\n" +
                    "        <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"" + idpLogoutUrl + "\"/>\n" +
                    "    </md:IDPSSODescriptor>\n" +
                    "</md:EntityDescriptor>";

            response.setContentType("application/xml");  // XML 콘텐츠 타입 설정

            if(downloadFlag != null && downloadFlag) {
                // 파일 다운로드
                String nowDateTime = getNowDateTime(false, null);
                response.setHeader("Content-Disposition", "attachment; filename=\"kt_idp_metadata_" + nowDateTime + ".xml\"");
                response.getWriter().write(idpMetadata);
            } else {
                // 화면 출력
                response.getWriter().print(idpMetadata);
            }

        } catch (Error e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "SAML 메타데이터 생성 오류");
        }
    }

    /** idp metadata download */
    @RequestMapping("/metadata/{channel}/download")
    public void downloadMetadata(HttpServletRequest request, HttpServletResponse response, @PathVariable String channel) throws Exception {
        getMetadata(request, response, channel, true);
    }

    // 특수문자 처리를 위한 함수
    String escapeXml(Object input) {
        return String.valueOf(input).replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }

    // cert 인증서 base64 변환
    String getBase64Cert(byte[] certBytes, Boolean lineBreaks) {
        String base64 = Base64.getEncoder().encodeToString(certBytes);

        if(lineBreaks != null && lineBreaks) {
            StringBuilder formattedBase64 = new StringBuilder();

            // 64자마다 개행을 추가
            for (int i = 0; i < base64.length(); i += 64) {
                int end = Math.min(i + 64, base64.length());
                formattedBase64.append(base64, i, end).append("\n");
            }

            return formattedBase64.toString();
        } else {
            return base64;
        }
    }

    // private key 가져오기
    PrivateKey getPrivateKey(String channel) throws Exception {
        File keyFile = getPrivateKeyFile(channel);

        // 파일에서 개인키를 읽어옵니다
        try (FileInputStream fileInputStream = new FileInputStream(keyFile)) {
            byte[] keyBytes = fileInputStream.readAllBytes();

            // PEM 형식일 경우 헤더와 푸터를 제거하고 Base64 디코딩
            String keyPem = new String(keyBytes);
            if (keyPem.startsWith("-----BEGIN PRIVATE KEY-----")) {
                keyPem = keyPem.replace("-----BEGIN PRIVATE KEY-----", "")
                        .replace("-----END PRIVATE KEY-----", "")
                        .replaceAll("\\s+", "")  // 공백과 줄바꿈 제거
                        .trim();
                keyBytes = Base64.getDecoder().decode(keyPem);
            }

            // 개인키 객체 생성
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return keyFactory.generatePrivate(spec);
        }
    }

    // private key 파일
    File getPrivateKeyFile(String channel) throws IOException {
        switch (channel) {
            case "udemy":
                return udemyPrivateKey.getFile();
            default:
                return null;
        }
    }

    // now date
    String getNowDateTime(Boolean tFlag, Long time) {
        ZonedDateTime now =  ZonedDateTime.now(ZoneOffset.UTC);

        if(time != null) {
            now = now.plusMinutes(time);
        }

        if(tFlag) {
            return now.format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'"));
        } else {
            return now.format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
        }
    }
}
