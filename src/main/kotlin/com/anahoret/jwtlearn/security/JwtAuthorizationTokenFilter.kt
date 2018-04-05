package com.anahoret.jwtlearn.security

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Lazy
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class JwtAuthorizationTokenFilter(
    @Lazy private val userDetailsService: UserDetailsService,
    private val jwtTokenUtil: JwtTokenUtil,
    @Value("\${jwt.header_name}") private val tokenHeaderName: String,
    @Value("\${jwt.header_prefix}") private val tokenHeaderPrefix: String
) : OncePerRequestFilter() {

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        request.getToken()
            ?.let { jwtTokenUtil.validateAndGetUsernameFromToken(it) }
            ?.let { username ->
                val securityContext = SecurityContextHolder.getContext()
                if (securityContext.authentication == null) {
                    logger.debug("security context was null, so authenticating user")
                    authenticateUser(securityContext, username, request)
                }
            }

        filterChain.doFilter(request, response)
    }

    private fun authenticateUser(securityContext: SecurityContext, username: String, request: HttpServletRequest) {
        val userDetails = userDetailsService.loadUserByUsername(username)
        val authentication = UsernamePasswordAuthenticationToken(userDetails, null, userDetails.authorities)
        authentication.details = WebAuthenticationDetailsSource().buildDetails(request)
        logger.info("authorized user '$username', setting security context")
        securityContext.authentication = authentication
    }

    private fun HttpServletRequest.getToken(): String? {
        return getHeader(tokenHeaderName)
            ?.takeIf { it.startsWith("$tokenHeaderPrefix ") }
            ?.substring(tokenHeaderPrefix.length + 1)
    }

}
