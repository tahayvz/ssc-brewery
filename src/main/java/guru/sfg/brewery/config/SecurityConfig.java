package guru.sfg.brewery.config;

//import guru.sfg.brewery.security.RestHeaderAuthFilter;
//import guru.sfg.brewery.security.RestUrlAuthFilter;
import guru.sfg.brewery.security.SfgPasswordEncoderFactories;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    public RestHeaderAuthFilter restHeaderAuthFilter(AuthenticationManager authenticationManager){
//        RestHeaderAuthFilter filter = new RestHeaderAuthFilter(new AntPathRequestMatcher("/api/**"));
//        filter.setAuthenticationManager(authenticationManager);
//        return filter;
//    }
//
//    public RestUrlAuthFilter restUrlAuthFilter(AuthenticationManager authenticationManager){
//        RestUrlAuthFilter filter = new RestUrlAuthFilter(new AntPathRequestMatcher("/api/**"));
//        filter.setAuthenticationManager(authenticationManager);
//        return filter;
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.addFilterBefore(restHeaderAuthFilter(authenticationManager()),
////                UsernamePasswordAuthenticationFilter.class);
//                UsernamePasswordAuthenticationFilter.class)
//                .csrf().disable();
//
//        http.addFilterBefore(restUrlAuthFilter(authenticationManager()),
//                UsernamePasswordAuthenticationFilter.class);

        http
                .authorizeRequests(authorize -> {
                    authorize
                            .antMatchers("/h2-console/**").permitAll() //do not use in production!
                            .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
                            .antMatchers("/beers/find", "/beers*").permitAll()
                            .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll()
                            .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll();
                } )
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().and()
                .httpBasic()
                .and().csrf().disable();

                //h2 console config
                http.headers().frameOptions().sameOrigin();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return SfgPasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("spring")
//                .password("{bcrypt}$2a$10$b.LK6FN2xk1FGNyQaPUMX.HYiQADhHY5ufhPluXuI5mKWBmhW3vUa")
//                .roles("ADMIN")
//                .and()
//                .withUser("user")
//                .password("{sha256}1c41d9a53f84d198b4406a1f81136f303adcd5a87dcfa1f3efb8263d95d46bef5f5b0cbbb6b0ff90")
//                .roles("USER");

//        auth.inMemoryAuthentication().withUser("scott").password("{bcrypt15}$2a$15$baOmQtw8UqWZRDQhMFPFj.xhkkWveCTQHe4OBdr8yw8QshejiSbI6").roles("CUSTOMER");
//        auth.inMemoryAuthentication().withUser("scott").password("{bcrypt10}$2a$10$tvgJyk6jLMwJ4cQa1zzkt.LWeYvcNvilF9Ej5XbIeWrCG8TzK49MS").roles("CUSTOMER");
//    }

    //    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails admin = User.withDefaultPasswordEncoder()
//                .username("spring")
//                .password("guru")
//                .roles("ADMIN")
//                .build();
//
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(admin, user);
//    }


}