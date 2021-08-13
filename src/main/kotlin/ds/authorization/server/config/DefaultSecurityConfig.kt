package ds.authorization.server.config

import org.springframework.context.annotation.Bean
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.cors.CorsConfiguration

@EnableWebSecurity
class DefaultSecurityConfig {

    @Bean
    @Throws(Exception::class)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .cors().configurationSource { CorsConfiguration().applyPermitDefaultValues() }
            .and()
            .authorizeRequests { authorizeRequests ->
                authorizeRequests.anyRequest().authenticated()
            }
            .formLogin(withDefaults())
        return http.build()
    }

    @Bean
    fun users(): UserDetailsService {
        val user: UserDetails = User.builder()
            .username("user")
            .password("password")
            .roles("USER")
            .passwordEncoder(passwordEncoder()::encode)
            .build()
        return InMemoryUserDetailsManager(user)
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

}