package com.popokis.backend_server

import com.popokis.backend_server.application.security.JWTService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.web.reactive.server.WebTestClient

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AppIntegrationTest {

    @Autowired
    protected lateinit var webTestClient: WebTestClient

    @Autowired
    protected lateinit var jwtService: JWTService

    protected fun accessToken() = accessToken("user@example.com")

    protected fun accessToken(email: String) = "Bearer " + jwtService.accessToken(email, 1000 * 60)
}