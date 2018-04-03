package com.anahoret.jwtlearn.security

import com.anahoret.jwtlearn.model.User
import org.springframework.security.core.authority.AuthorityUtils

object JwtUserFactory {

    fun create(user: User): JwtUser {
        return JwtUser(
            user.username,
            user.password,
            AuthorityUtils.commaSeparatedStringToAuthorityList(user.authorities)
        )
    }

}
