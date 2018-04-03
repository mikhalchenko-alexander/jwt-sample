package com.anahoret.jwtlearn.security

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Lazy
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken

@Component
class JwtAuthorizationTokenFilter(
    @Lazy private val userDetailsService: UserDetailsService,
    private val jwtTokenUtil: JwtTokenUtil,
    @Value("\${jwt.header_name}") private val tokenHeaderName: String,
    @Value("\${jwt.header_prefix}") private val tokenHeaderPrefix: String
) : OncePerRequestFilter() {

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val requestHeader = request.getHeader(tokenHeaderName)
        requestHeader?.takeIf { it.startsWith("$tokenHeaderPrefix ") }
            ?.substring(tokenHeaderPrefix.length + 1)
            ?.let { token ->
                jwtTokenUtil.getUsernameFromToken(token)
                    ?.let { it.takeIf { SecurityContextHolder.getContext().authentication == null } }
                    ?.let { username ->
                        logger.debug("security context was null, so authorizating user")
                        val userDetails = userDetailsService.loadUserByUsername(username)
                        if (jwtTokenUtil.validateToken(token, userDetails)) {
                            val authentication = UsernamePasswordAuthenticationToken(userDetails, null, userDetails.authorities)
                            authentication.details = WebAuthenticationDetailsSource().buildDetails(request)
                            logger.info("authorized user '$username', setting security context")
                            SecurityContextHolder.getContext().authentication = authentication
                        }
                    }

            }

        filterChain.doFilter(request, response)
    }

}
