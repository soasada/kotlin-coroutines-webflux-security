package com.popokis.backend_server.application.login

import com.popokis.backend_server.AppIntegrationTest
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Value

internal class LoginIntegrationTest : AppIntegrationTest() {

    @Value("\${app.first_user.username}")
    private lateinit var firstUsername: String

    @Value("\${app.first_user.password}")
    private lateinit var firstPassword: String

    @Test
    fun `Given an existing customer when tries to login then get an access and refresh token`() {
        val responseHeaders = webTestClient
                .post().uri("/login")
                .bodyValue(LoginRequest(firstUsername, firstPassword))
                .exchange()
                .expectStatus().isOk
                .expectHeader().exists("Authorization")
                .expectHeader().exists("JWT-Refresh-Token")
                .expectBody().returnResult().responseHeaders

        val accessToken = responseHeaders["Authorization"]?.get(0)
        val refreshToken = responseHeaders["JWT-Refresh-Token"]?.get(0)

        jwtService.decodeAccessToken(accessToken!!)
        jwtService.decodeRefreshToken(refreshToken!!)
    }

    @Test
    fun `Given an unknown customer when try to login then receives an UNAUTHORIZED error`() {
        webTestClient
                .post().uri("/login")
                .bodyValue(LoginRequest("unknown@example.com", "unknownpassword"))
                .exchange()
                .expectStatus().isUnauthorized
    }

    @Test
    fun `Given a customer when tries to login with a username that is not a valid email then receives BAD REQUEST error`() {
        webTestClient
                .post().uri("/login")
                .bodyValue(LoginRequest("invalid@asd", "invalid"))
                .exchange()
                .expectStatus().isBadRequest
    }

    @Test
    fun `Given a customer when tries to login with correct email but not sized password then receives BAD REQUEST error`() {
        webTestClient
                .post().uri("/login")
                .bodyValue(LoginRequest("invalid@asd.com", "invalid"))
                .exchange()
                .expectStatus().isBadRequest
    }

    @Test
    fun `Given a customer when tries to login with correct email but incorrect password then receives BAD REQUEST error`() {
        webTestClient
                .post().uri("/login")
                .bodyValue(LoginRequest(firstUsername, "invalidpassword"))
                .exchange()
                .expectStatus().isUnauthorized
    }

    @Test
    fun `Given a customer when tries to login with incorrect JSON request then receives BAD REQUEST error`() {
        val badRequest = object {
            val invalidUsername = "invalid@asd.com"
            val password = "invalid"
        }

        webTestClient
                .post().uri("/login")
                .bodyValue(badRequest)
                .exchange()
                .expectStatus().isBadRequest
    }

    @Test
    fun `Given a customer when tries to login making a GET request then receives NOT FOUND error`() {
        webTestClient
                .get().uri("/login")
                .exchange()
                .expectStatus().isNotFound
    }
}