package com.anahoret.jwtlearn.controller

import org.springframework.security.access.annotation.Secured
import org.springframework.stereotype.Controller
import org.springframework.util.MimeTypeUtils
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ResponseBody

@Controller
class IndexController {

    @GetMapping("", "/", produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    @ResponseBody
    fun index() = mapOf("message" to "Hello, JWT!")

    @GetMapping("secured", produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    @ResponseBody
    @Secured("ROLE_ADMIN")
    fun protected() = mapOf("message" to "Welcome to secured area!")

}
