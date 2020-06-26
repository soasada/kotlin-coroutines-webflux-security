package com.popokis.backend_server.application.security.authentication

import com.popokis.backend_server.application.HttpExceptionFactory
import kotlinx.coroutines.reactive.awaitFirstOrNull
import kotlinx.coroutines.reactor.mono
import org.springframework.http.HttpStatus
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component
class JWTServerAuthenticationFailureHandler : ServerAuthenticationFailureHandler {
    override fun onAuthenticationFailure(webFilterExchange: WebFilterExchange?, exception: AuthenticationException?): Mono<Void> = mono {
        val exchange = webFilterExchange?.exchange ?: throw HttpExceptionFactory.unauthorized()
        exchange.response.statusCode = HttpStatus.UNAUTHORIZED
        exchange.response.setComplete().awaitFirstOrNull()
    }
}