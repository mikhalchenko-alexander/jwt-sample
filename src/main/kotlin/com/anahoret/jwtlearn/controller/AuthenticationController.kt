package com.anahoret.jwtlearn.controller

import com.anahoret.jwtlearn.security.JwtTokenUtil
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody

@Controller
class AuthenticationController(
    private val authenticationManager: AuthenticationManager,
    private val userDetailsService: UserDetailsService,
    private val jwtTokenUtil: JwtTokenUtil
) {

    private val logger = LoggerFactory.getLogger(AuthenticationController::class.java)

    @PostMapping("auth")
    fun authenticate(@RequestBody authenticationRequest: AuthenticationRequest?): ResponseEntity<*> {
        return authenticationRequest?.let { (username, password) ->
            try {
                authenticationManager.authenticate(UsernamePasswordAuthenticationToken(username, password))
                val userDetails = userDetailsService.loadUserByUsername(username)
                val token = jwtTokenUtil.createToken(userDetails);
                ResponseEntity.ok(JwtAuthenticationResponse(token));
            } catch (e: AuthenticationException) {
                logger.debug("Authentication error", e)
                null
            }
        } ?: ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(AuthenticationError("Bad credentials"))
    }

    data class AuthenticationRequest(val username: String? = null, val password: String? = null)
    class AuthenticationError(val error: String)
    class JwtAuthenticationResponse(val token: String)

}
