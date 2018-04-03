package com.anahoret.jwtlearn.controller

import com.anahoret.jwtlearn.security.JwtTokenUtil
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.userdetails.UserDetailsService

@Controller
class AuthenticationController(
    private val authenticationManager: AuthenticationManager,
    private val userDetailsService: UserDetailsService,
    private val jwtTokenUtil: JwtTokenUtil
) {

    @PostMapping("auth")
    fun authenticate(@RequestBody authenticationRequest: AuthenticationRequest): ResponseEntity<*> {
        authenticationManager.authenticate(UsernamePasswordAuthenticationToken(
            authenticationRequest.username, authenticationRequest.password))

        val userDetails = userDetailsService.loadUserByUsername(authenticationRequest.username);
        val token = jwtTokenUtil.createToken(userDetails);

        return ResponseEntity.ok(JwtAuthenticationResponse(token));
    }

    class AuthenticationRequest(val username: String, val password: String)
    class JwtAuthenticationResponse(val token: String)

}
