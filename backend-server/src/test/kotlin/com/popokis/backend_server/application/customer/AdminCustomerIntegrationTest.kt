package com.popokis.backend_server.application.customer

import com.popokis.backend_server.AppIntegrationTest
import com.popokis.backend_server.domain.Customer
import com.popokis.backend_server.domain.CustomerRepository
import com.popokis.backend_server.helper.CustomerHelper
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpHeaders
import org.springframework.test.web.reactive.server.expectBodyList

internal class AdminCustomerIntegrationTest(@Autowired private val customerRepository: CustomerRepository) : AppIntegrationTest() {

    @Test
    fun `Given a customer with USER role when tries to fetch data from admin customers API then receives an UNAUTHORIZED error`() {
        webTestClient
                .get().uri("/admin/customers")
                .header(HttpHeaders.AUTHORIZATION, accessToken())
                .exchange()
                .expectStatus().isUnauthorized
    }

    @Test
    fun `Given a customer with ADMIN role when tries to fetch data from admin customers API with AUTHORIZATION then receives the data`() {
        runBlocking {
            val customer = CustomerHelper.random()

            customerRepository.save(customer)

            webTestClient
                    .get().uri("/admin/customers")
                    .header(HttpHeaders.AUTHORIZATION, adminAccessToken())
                    .exchange()
                    .expectStatus().isOk
                    .expectBodyList<Customer>()
                    .contains(customer)
        }
    }
}