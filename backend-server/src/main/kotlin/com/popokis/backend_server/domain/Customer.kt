package com.popokis.backend_server.domain

import org.springframework.data.annotation.CreatedDate
import org.springframework.data.annotation.Id
import org.springframework.data.annotation.LastModifiedDate
import org.springframework.data.mongodb.core.index.Indexed
import org.springframework.data.mongodb.core.mapping.Document
import java.time.Instant

@Document
data class Customer(@Id val id: String,
                    @Indexed(unique = true) val email: String,
                    val password: String,
                    @CreatedDate val createdAt: Instant = Instant.now(),
                    @LastModifiedDate val updatedAt: Instant = Instant.now()) {
    override fun equals(other: Any?) = other is Customer && EssentialCustomerData(this) == EssentialCustomerData(other)
    override fun hashCode() = EssentialCustomerData(this).hashCode()
}

private data class EssentialCustomerData(val id: String) {
    constructor(customer: Customer) : this(customer.id)
}