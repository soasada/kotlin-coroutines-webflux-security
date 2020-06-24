package com.popokis.backend_server.infrastructure

import com.popokis.backend_server.domain.Customer
import org.springframework.data.mongodb.repository.ReactiveMongoRepository
import reactor.core.publisher.Mono

interface CustomerSpringMongoRepository : ReactiveMongoRepository<Customer, String> {
    fun findCustomerByEmail(email: String): Mono<Customer>
}