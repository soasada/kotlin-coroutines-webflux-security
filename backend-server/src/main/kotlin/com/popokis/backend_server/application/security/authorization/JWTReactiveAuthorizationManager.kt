package com.popokis.backend_server.application.security.authorization

import com.auth0.jwt.interfaces.DecodedJWT
import com.popokis.backend_server.application.security.JWTService
import kotlinx.coroutines.reactor.mono
import org.springframework.http.HttpHeaders
import org.springframework.security.authorization.AuthorizationDecision
import org.springframework.security.authorization.ReactiveAuthorizationManager
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.authorization.AuthorizationContext
import reactor.core.publisher.Mono

interface JWTReactiveAuthorizationManager : ReactiveAuthorizationManager<AuthorizationContext> {

    override fun check(authentication: Mono<Authentication>?, context: AuthorizationContext?): Mono<AuthorizationDecision> = mono {
        val notAuthorized = AuthorizationDecision(false)
        val exchange = context?.exchange ?: return@mono notAuthorized
        val authHeader = exchange.request.headers.getFirst(HttpHeaders.AUTHORIZATION) ?: return@mono notAuthorized

        if (!authHeader.startsWith("Bearer ")) {
            return@mono notAuthorized
        }

        try {
            return@mono doAuthorization(getJwtService().decodeAccessToken(authHeader))
        } catch (e: Throwable) {
            return@mono notAuthorized
        }
    }

    suspend fun getJwtService(): JWTService
    suspend fun doAuthorization(jwtToken: DecodedJWT): AuthorizationDecision
}