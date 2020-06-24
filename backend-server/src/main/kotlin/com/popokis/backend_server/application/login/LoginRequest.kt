package com.popokis.backend_server.application.login

import javax.validation.constraints.Email
import javax.validation.constraints.NotBlank
import javax.validation.constraints.Size

data class LoginRequest(
        @field:Email(regexp = ".+@.+\\..+")
        @field:NotBlank
        val username: String,
        @field:NotBlank
        @field:Size(min = 8, max = 255)
        val password: String
)