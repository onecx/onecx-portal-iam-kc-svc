package io.github.onecx.portal.iam.kc.rs.v1.controllers;

import static io.restassured.RestAssured.given;

import org.junit.jupiter.api.Test;

import io.github.onecx.portal.iam.test.AbstractKeycloakAminTest;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.keycloak.client.KeycloakTestClient;
import io.restassured.http.ContentType;

@QuarkusTest
class KeycloakAdminRestControllerPasswordTest extends AbstractKeycloakAminTest {

    KeycloakTestClient keycloakClient = new KeycloakTestClient();

    @Test
    void resetPasswordRequestValidationTest() {
        String accessToken = keycloakClient.getAccessToken(USER_ALICE);

        // null body
        given().auth()
                .oauth2(accessToken)
                .contentType(ContentType.JSON)
                .put("/v1/iam/reset-password")
                .then().statusCode(400);

        // null password
        given().auth()
                .oauth2(accessToken)
                .body(new KeycloakAdminRestController.ResetPasswordRequestDTO(null))
                .contentType(ContentType.JSON)
                .put("/v1/iam/reset-password")
                .then().statusCode(400);

        // empty password
        given().auth()
                .oauth2(accessToken)
                .body(new KeycloakAdminRestController.ResetPasswordRequestDTO(""))
                .contentType(ContentType.JSON)
                .put("/v1/iam/reset-password")
                .then().statusCode(400);
    }

    @Test
    void resetPasswordTest() {
        String newPassword = "changedPassword";

        String accessToken = keycloakClient.getAccessToken(USER_ALICE);

        given().auth()
                .oauth2(accessToken)
                .body(new KeycloakAdminRestController.ResetPasswordRequestDTO(newPassword))
                .contentType(ContentType.JSON)
                .put("/v1/iam/reset-password")
                .then().statusCode(204);

        accessToken = keycloakClient.getAccessToken(USER_ALICE, newPassword, getClientId());

        given().auth()
                .oauth2(accessToken)
                .body(new KeycloakAdminRestController.ResetPasswordRequestDTO(PASSWORD_ALICE))
                .contentType(ContentType.JSON)
                .put("/v1/iam/reset-password")
                .then().statusCode(204);

        keycloakClient.getAccessToken(USER_ALICE);
    }

}
