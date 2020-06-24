package com.popokis.backend_server.application.security.authentication

import com.popokis.backend_server.application.HttpExceptionFactory.badRequest
import com.popokis.backend_server.application.login.LoginRequest
import kotlinx.coroutines.reactive.awaitFirstOrNull
import kotlinx.coroutines.reactor.mono
import org.springframework.core.ResolvableType
import org.springframework.http.MediaType
import org.springframework.http.codec.json.AbstractJackson2Decoder
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import javax.validation.Validator

@Component
class JWTConverter(private val jacksonDecoder: AbstractJackson2Decoder,
                   private val validator: Validator) : ServerAuthenticationConverter {
    override fun convert(exchange: ServerWebExchange?): Mono<Authentication> = mono {
        val loginRequest = getUsernameAndPassword(exchange!!) ?: throw badRequest()

        if (validator.validate(loginRequest).isNotEmpty()) {
            throw badRequest()
        }

        return@mono UsernamePasswordAuthenticationToken(loginRequest.username, loginRequest.password)
    }

    private suspend fun getUsernameAndPassword(exchange: ServerWebExchange): LoginRequest? {
        val dataBuffer = exchange.request.body
        val type = ResolvableType.forClass(LoginRequest::class.java)
        return jacksonDecoder
                .decodeToMono(dataBuffer, type, MediaType.APPLICATION_JSON, mapOf())
                .onErrorResume { Mono.empty<LoginRequest>() }
                .cast(LoginRequest::class.java)
                .awaitFirstOrNull()
    }
}
