package com.popokis.backend_server.helper

import com.popokis.backend_server.domain.Customer
import java.util.UUID

object CustomerHelper {

    fun random() = Customer(
            UUID.randomUUID().toString(),
            UUID.randomUUID().toString() + "@example.com",
            UUID.randomUUID().toString()
    )
}