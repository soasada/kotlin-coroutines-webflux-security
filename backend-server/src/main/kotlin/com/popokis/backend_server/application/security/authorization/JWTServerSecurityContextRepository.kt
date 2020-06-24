package com.popokis.backend_server.application.security.authorization

import com.popokis.backend_server.application.HttpExceptionFactory.unauthorized
import com.popokis.backend_server.application.security.JWTService
import kotlinx.coroutines.reactor.mono
import org.springframework.http.HttpHeaders
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@Component
class JWTServerSecurityContextRepository(private val jwtService: JWTService) : ServerSecurityContextRepository {

    override fun save(exchange: ServerWebExchange?, securityContext: SecurityContext?): Mono<Void> {
        return Mono.empty()
    }

    override fun load(exchange: ServerWebExchange?): Mono<SecurityContext> = mono {
        val authHeader = exchange?.request?.headers?.getFirst(HttpHeaders.AUTHORIZATION) ?: throw unauthorized()

        if (!authHeader.startsWith("Bearer ")) {
            throw unauthorized()
        }

        try {
            val decodedJWT = jwtService.decodeAccessToken(authHeader)

            if (decodedJWT.subject.isNullOrBlank()) {
                throw unauthorized()
            }

            return@mono SecurityContextImpl(UsernamePasswordAuthenticationToken(decodedJWT.subject, null, listOf()))
        } catch (e: Throwable) {
            throw unauthorized()
        }
    }
}