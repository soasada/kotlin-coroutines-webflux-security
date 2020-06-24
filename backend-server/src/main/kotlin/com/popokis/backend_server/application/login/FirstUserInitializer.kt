package com.popokis.backend_server.application.login

import com.popokis.backend_server.domain.Customer
import com.popokis.backend_server.domain.CustomerRepository
import kotlinx.coroutines.runBlocking
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.context.event.ApplicationReadyEvent
import org.springframework.context.event.EventListener
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Component
import java.util.UUID

@Component
class FirstUserInitializer(
        private val customerRepository: CustomerRepository,
        private val passwordEncoder: PasswordEncoder,
        @Value("\${app.first_user.username}") val firstUsername: String,
        @Value("\${app.first_user.password}") val firstPassword: String) {

    private val logger: Logger = LoggerFactory.getLogger(javaClass)

    @EventListener(ApplicationReadyEvent::class)
    fun init() {
        runBlocking {
            val firstCustomer = customerRepository.findByEmail(firstUsername)

            if (null == firstCustomer) {
                customerRepository.save(Customer(UUID.randomUUID().toString(), firstUsername, passwordEncoder.encode(firstPassword)))
                logger.info("First customer created: $firstUsername")
            } else {
                logger.info("First customer already created")
            }
        }
    }
}