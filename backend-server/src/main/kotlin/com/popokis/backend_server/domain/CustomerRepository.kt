package com.popokis.backend_server.domain

import kotlinx.coroutines.flow.Flow

interface CustomerRepository {
    suspend fun save(customer: Customer): Customer
    fun all(): Flow<Customer>
    suspend fun findByEmail(email: String): Customer?
}