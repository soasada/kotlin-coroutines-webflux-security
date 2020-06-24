package com.popokis.backend_server.application

import org.springframework.http.HttpStatus
import org.springframework.web.server.ResponseStatusException

object HttpExceptionFactory {

    fun notFound(): ResponseStatusException = ResponseStatusException(HttpStatus.NOT_FOUND, "Not found")

    fun badRequest(): ResponseStatusException = ResponseStatusException(HttpStatus.BAD_REQUEST, "Bad Request")

    fun unauthorized(): ResponseStatusException = ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized")
}