package com.anahoret.jwtlearn.service

import com.anahoret.jwtlearn.model.User
import com.anahoret.jwtlearn.security.JwtUserFactory
import org.springframework.context.annotation.Primary
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
@Primary
class JwtUserDetailsService(passwordEncoder: PasswordEncoder) : UserDetailsService {

    private val users =
        mapOf(
            "hank" to User("hank", passwordEncoder.encode("hank"), "ROLE_ADMIN"),
            "dale" to User("dale", passwordEncoder.encode("dale"), "ROLE_USER"),
            "bill" to User("bill", passwordEncoder.encode("bill"), "ROLE_USER"),
            "boomhauer" to User("boomhauer", passwordEncoder.encode("boomhauer"), "ROLE_USER")
        )

    override fun loadUserByUsername(username: String?): UserDetails {
        return username?.let { users[it] }
            ?.let { JwtUserFactory.create(it) }
            ?: throw UsernameNotFoundException("No user found with username '$username'.")
    }

}
