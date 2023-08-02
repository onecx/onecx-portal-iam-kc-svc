package io.github.onecx.portal.iam.kc.rs.v1.controllers;

import static io.github.onecx.portal.iam.kc.rs.v1.controllers.Security.ROLE_PORTAL_ADMIN;
import static io.restassured.RestAssured.given;

import org.junit.jupiter.api.Test;

import io.quarkus.test.common.http.TestHTTPEndpoint;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import io.quarkus.test.security.oidc.Claim;
import io.quarkus.test.security.oidc.OidcSecurity;
import io.restassured.http.ContentType;

@QuarkusTest
@TestHTTPEndpoint(KeycloakAdminRestController.class)
class KeycloakAdminRestControllerSecurityTest {

    @Test
    @TestSecurity(user = "testUser", roles = "viewer")
    @OidcSecurity(claims = {
            @Claim(key = "sub", value = "testUser")
    })
    void resetPasswordNoRolesTest() {
        given().body(new KeycloakAdminRestController.ResetPasswordRequestDTO("test"))
                .contentType(ContentType.JSON)
                .put("reset-password")
                .then().statusCode(403);
    }

    @Test
    @TestSecurity(user = "testUser", roles = ROLE_PORTAL_ADMIN)
    @OidcSecurity(claims = {
            @Claim(key = "email", value = "testUser@test")
    })
    void resetPasswordAdminRoleNoUserTest() {
        given().body(new KeycloakAdminRestController.ResetPasswordRequestDTO("test"))
                .contentType(ContentType.JSON)
                .put("reset-password")
                .then().statusCode(401);
    }

    @Test
    @TestSecurity(user = "testUser", roles = ROLE_PORTAL_ADMIN)
    @OidcSecurity(claims = {
            @Claim(key = "sub", value = "")
    })
    void resetPasswordAdminRoleEmptyUserTest() {
        given().body(new KeycloakAdminRestController.ResetPasswordRequestDTO("test"))
                .contentType(ContentType.JSON)
                .put("reset-password")
                .then().statusCode(401);
    }

    @Test
    @TestSecurity(user = "testUser", roles = ROLE_PORTAL_ADMIN)
    @OidcSecurity(claims = {
            @Claim(key = "sub", value = "testUser")
    })
    void resetPasswordAdminRoleNoIssuerTest() {
        given().body(new KeycloakAdminRestController.ResetPasswordRequestDTO("test"))
                .contentType(ContentType.JSON)
                .put("reset-password")
                .then().statusCode(401);
    }

    @Test
    @TestSecurity(user = "testUser", roles = ROLE_PORTAL_ADMIN)
    @OidcSecurity(claims = {
            @Claim(key = "sub", value = "testUser"),
            @Claim(key = "iss", value = "")
    })
    void resetPasswordAdminRoleEmptyIssuerTest() {
        given().body(new KeycloakAdminRestController.ResetPasswordRequestDTO("test"))
                .contentType(ContentType.JSON)
                .put("reset-password")
                .then().statusCode(401);
    }

    @Test
    @TestSecurity(user = "testUser", roles = ROLE_PORTAL_ADMIN)
    @OidcSecurity(claims = {
            @Claim(key = "sub", value = "testUser"),
            @Claim(key = "iss", value = "testUser")
    })
    void resetPasswordAdminRoleWrongIssuerTest() {
        given().body(new KeycloakAdminRestController.ResetPasswordRequestDTO("test"))
                .contentType(ContentType.JSON)
                .put("reset-password")
                .then().statusCode(401);
    }

    @Test
    @TestSecurity(user = "testUser", roles = ROLE_PORTAL_ADMIN)
    @OidcSecurity(claims = {
            @Claim(key = "sub", value = "testUser"),
            @Claim(key = "iss", value = "testUser/")
    })
    void resetPasswordAdminRoleWrongUrlIssuerTest() {
        given().body(new KeycloakAdminRestController.ResetPasswordRequestDTO("test"))
                .contentType(ContentType.JSON)
                .put("reset-password")
                .then().statusCode(401);
    }

    @Test
    @TestSecurity(user = "testUser", roles = ROLE_PORTAL_ADMIN)
    @OidcSecurity(claims = {
            @Claim(key = "sub", value = "testUser"),
            @Claim(key = "iss", value = "testUser/test")
    })
    void resetPasswordAdminRoleIssuerTest() {
        given().body(new KeycloakAdminRestController.ResetPasswordRequestDTO("test"))
                .contentType(ContentType.JSON)
                .put("reset-password")
                .then().statusCode(500);
    }
}
