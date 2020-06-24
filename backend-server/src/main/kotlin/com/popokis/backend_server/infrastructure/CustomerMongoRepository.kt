package com.popokis.backend_server.infrastructure

import com.popokis.backend_server.domain.Customer
import com.popokis.backend_server.domain.CustomerRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.reactive.asFlow
import kotlinx.coroutines.reactive.awaitFirstOrNull
import kotlinx.coroutines.reactive.awaitSingle
import org.springframework.stereotype.Repository

@Repository
class CustomerMongoRepository(private val customerSpringMongoRepository: CustomerSpringMongoRepository) : CustomerRepository {

    override suspend fun save(customer: Customer): Customer {
        return customerSpringMongoRepository.insert(customer).awaitSingle()
    }

    override fun all(): Flow<Customer> {
        return customerSpringMongoRepository.findAll().asFlow()
    }

    override suspend fun findByEmail(email: String): Customer? {
        return customerSpringMongoRepository.findCustomerByEmail(email).awaitFirstOrNull()
    }
}