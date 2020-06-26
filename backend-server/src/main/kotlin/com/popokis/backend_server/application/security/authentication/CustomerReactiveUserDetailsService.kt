package com.popokis.backend_server.application.security.authentication

import com.popokis.backend_server.domain.CustomerRepository
import kotlinx.coroutines.reactor.mono
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono

@Service
class CustomerReactiveUserDetailsService(private val customerRepository: CustomerRepository) : ReactiveUserDetailsService {

    override fun findByUsername(username: String?): Mono<UserDetails> = mono {
        val customer = customerRepository.findByEmail(username!!) ?: throw BadCredentialsException("Invalid Credentials")
        return@mono User(customer.email, customer.password, listOf())
    }
}