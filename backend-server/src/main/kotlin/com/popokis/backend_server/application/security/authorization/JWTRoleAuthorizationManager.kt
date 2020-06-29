package com.popokis.backend_server.application.security.authorization

import com.auth0.jwt.interfaces.DecodedJWT
import com.popokis.backend_server.application.security.JWTService
import org.springframework.security.authorization.AuthorizationDecision

class JWTRoleAuthorizationManager(private val jwtService: JWTService, private val role: String) : JWTReactiveAuthorizationManager {
    override suspend fun getJwtService(): JWTService {
        return jwtService
    }

    override suspend fun doAuthorization(jwtToken: DecodedJWT): AuthorizationDecision {
        return AuthorizationDecision(jwtService.getRoles(jwtToken).any { it.authority == "ROLE_$role" })
    }
}