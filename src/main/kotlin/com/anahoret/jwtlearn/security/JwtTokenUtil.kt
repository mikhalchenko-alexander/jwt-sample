package com.anahoret.jwtlearn.security

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component

@Component
class JwtTokenUtil(
    @Value("\${jwt.secret}") private val secret: String
) {

    private val algorithm = Algorithm.HMAC256(secret)

    fun createToken(userDetails: UserDetails): String {
        return JWT.create()
            .withSubject(userDetails.username)
            .withArrayClaim("authorities", userDetails.authorities.map { it.authority }.toTypedArray())
            .sign(algorithm)
    }

    fun validateToken(token: String, userDetails: UserDetails): Boolean {
        return verifyAndDecode(token) != null
    }

    fun getUsernameFromToken(token: String): String? {
        return verifyAndDecode(token)?.subject
    }

    private fun verifyAndDecode(token: String): DecodedJWT? {
        return try {
            JWT.require(algorithm)
                .build()
                .verify(token)
        } catch (t: Throwable) {
            null
        }
    }

}
