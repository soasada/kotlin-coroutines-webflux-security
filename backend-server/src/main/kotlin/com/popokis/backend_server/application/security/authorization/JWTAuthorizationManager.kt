package com.popokis.backend_server.application.security.authorization

import com.popokis.backend_server.application.security.JWTService
import kotlinx.coroutines.reactor.mono
import org.springframework.http.HttpHeaders
import org.springframework.security.authorization.AuthorizationDecision
import org.springframework.security.authorization.ReactiveAuthorizationManager
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.authorization.AuthorizationContext
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component
class JWTAuthorizationManager(private val jwtService: JWTService) : ReactiveAuthorizationManager<AuthorizationContext> {
    override fun check(authentication: Mono<Authentication>?, context: AuthorizationContext?): Mono<AuthorizationDecision> = mono {
        val exchange = context?.exchange ?: return@mono AuthorizationDecision(false)
        val authHeader = exchange.request.headers.getFirst(HttpHeaders.AUTHORIZATION) ?: return@mono AuthorizationDecision(false)

        if (!authHeader.startsWith("Bearer ")) {
            return@mono AuthorizationDecision(false)
        }

        try {
            jwtService.decodeAccessToken(authHeader)
            return@mono AuthorizationDecision(true)
        } catch (e: Throwable) {
            return@mono AuthorizationDecision(false)
        }
    }
}