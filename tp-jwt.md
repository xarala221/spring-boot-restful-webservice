# Securiser un webservice Rest avec JWT

Clonnes le projet et fais des tests -:)

## TP:1

### Créer les models

Dans le Fichier ```pom.xml```, ajoutez le code suivant

```xml
<dependency>
  <groupId>io.jsonwebtoken</groupId>
  <artifactId>jjwt</artifactId>
  <version>0.9.1</version>
</dependency>
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
  <groupId>javax.validation</groupId>
  <artifactId>validation-api</artifactId>
  <version>2.0.1.Final</version>
</dependency>
```

Mettez à jour le fichier ```application.properties```

```maven

spring.datasource.url= jdbc:postgresql://localhost:5432/<base de donnees>
spring.datasource.username= <utilisateur>
spring.datasource.password= <mot de passe>

spring.jpa.properties.hibernate.jdbc.lob.non_contextual_creation= true
spring.jpa.properties.hibernate.dialect= org.hibernate.dialect.PostgreSQLDialect

# Hibernate ddl auto (create, create-drop, validate, update)
spring.jpa.hibernate.ddl-auto= update

# App Properties
xarala.app.jwtSecret= bezKoderSecretKey
xarala.app.jwtExpirationMs= 86400000

```

Nous allons créer  3 classes ```ERole.Java``` , ```Role.Java``` et ```User.Java```.

ERole.Java

```java
package co.xarala.models;

public enum ERole {
  ROLE_USER,
    ROLE_MODERATOR,
    ROLE_ADMIN
}
```

Role.java

```java
package co.xarala.models;

import javax.persistence.*;

@Entity
@Table(name = "roles")
public class Role {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Integer id;

  @Enumerated(EnumType.STRING)
  @Column(length = 20)
  private ERole name;

  public Role() {

  }

  public Role(ERole name) {
  this.name = name;
  }

  public Integer getId() {
  return id;
  }

  public void setId(Integer id) {
  this.id = id;
  }

  public ERole getName() {
  return name;
  }

  public void setName(ERole name) {
  this.name = name;
  }
}
```

User.java

```java
package co.xarala.models;

import java.util.HashSet;
import java.util.Set;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Entity
@Table(name = "users",
  uniqueConstraints = {
  @UniqueConstraint(columnNames = "username"),
  @UniqueConstraint(columnNames = "email")
  })
public class User {
@Id
@GeneratedValue(strategy = GenerationType.IDENTITY)
private Long id;

@NotBlank
@Size(max = 20)
private String username;

@NotBlank
@Size(max = 50)
@Email
private String email;

@NotBlank
@Size(max = 120)
private String password;

@ManyToMany(fetch = FetchType.LAZY)
@JoinTable(name = "user_roles",
  joinColumns = @JoinColumn(name = "user_id"),
  inverseJoinColumns = @JoinColumn(name = "role_id"))
private Set<Role> roles = new HashSet<>();

public User() {
}

public User(String username, String email, String password) {
  this.username = username;
  this.email = email;
  this.password = password;
}

public Long getId() {
  return id;
}

public void setId(Long id) {
  this.id = id;
}

public String getUsername() {
  return username;
}

public void setUsername(String username) {
  this.username = username;
}

public String getEmail() {
  return email;
}

public void setEmail(String email) {
  this.email = email;
}

public String getPassword() {
  return password;
}

public void setPassword(String password) {
  this.password = password;
}

public Set<Role> getRoles() {
  return roles;
}

public void setRoles(Set<Role> roles) {
  this.roles = roles;
}
}
```

### Mettre en œuvre des référentiels(repositories)

Nous allons créer deux Repositories pour les models ```User``` et ```Role```.

UserRepository.java

```java
package co.xarala.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import co.xarala.models.User;


@Repository
public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByUsername(String username);

  Boolean existsByUsername(String username);

  Boolean existsByEmail(String email);
}
```

RoleRepository.java

```java
package co.xarala.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import co.xarala.models.ERole;
import co.xarala.models.Role;



@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
  Optional<Role> findByName(ERole name);
}
```

### Configurer Spring Security

Créez un nouveau package et appel le ```security```.
Dans ce package, créez la classe WebSecurityConfig qui étend WebSecurityConfigurerAdapter.

WebSecurityConfig.java

```java
package co.xarala.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import co.xarala.security.jwt.AuthEntryPointJwt;
import co.xarala.security.jwt.AuthTokenFilter;
import co.xarala.security.services.UserDetailsServiceImpl;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
// securedEnabled = true,
// jsr250Enabled = true,
prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
@Autowired
UserDetailsServiceImpl userDetailsService;

@Autowired
private AuthEntryPointJwt unauthorizedHandler;

@Bean
public AuthTokenFilter authenticationJwtTokenFilter() {
return new AuthTokenFilter();
}

@Override
public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
}

@Bean
@Override
public AuthenticationManager authenticationManagerBean() throws Exception {
return super.authenticationManagerBean();
}

@Bean
public PasswordEncoder passwordEncoder() {
return new BCryptPasswordEncoder();
}

@Override
protected void configure(HttpSecurity http) throws Exception {
http.cors().and().csrf().disable()
  .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
  .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
  .authorizeRequests().antMatchers("/api/auth/**").permitAll()
  .antMatchers("/api/**").permitAll()
  .anyRequest().authenticated();

http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
}
}
```

Créez deux sous-dossier dans security ```services``` et ```jwt```.

Implement **UserDetails** & **UserDetailsService**

Filter les **requetes**

Dans le package **jwt**, ajoutez AuthTokenFilter.

AuthTokenFilter.java

```java
package co.xarala.security.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import co.xarala.security.services.UserDetailsServiceImpl;

public class AuthTokenFilter extends OncePerRequestFilter {
@Autowired
private JwtUtils jwtUtils;

@Autowired
private UserDetailsServiceImpl userDetailsService;

private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

@Override
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
throws ServletException, IOException {
try {
String jwt = parseJwt(request);
if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
String username = jwtUtils.getUserNameFromJwtToken(jwt);

UserDetails userDetails = userDetailsService.loadUserByUsername(username);
UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
userDetails, null, userDetails.getAuthorities());
authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

SecurityContextHolder.getContext().setAuthentication(authentication);
}
} catch (Exception e) {
logger.error("Cannot set user authentication: {}", e);
}

filterChain.doFilter(request, response);
}

private String parseJwt(HttpServletRequest request) {
String headerAuth = request.getHeader("Authorization");

if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
return headerAuth.substring(7, headerAuth.length());
}

return null;
}
}

```

Créer une classe utilitaire dans le package **jwt**

JwtUtils.java

```java
package co.xarala.security.jwt;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import co.xarala.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;

@Component
public class JwtUtils {
private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

@Value("${xarala.app.jwtSecret}")
private String jwtSecret;

@Value("${xarala.app.jwtExpirationMs}")
private int jwtExpirationMs;

public String generateJwtToken(Authentication authentication) {

UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

return Jwts.builder()
.setSubject((userPrincipal.getUsername()))
.setIssuedAt(new Date())
.setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
.signWith(SignatureAlgorithm.HS512, jwtSecret)
.compact();
}

public String getUserNameFromJwtToken(String token) {
return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
}

public boolean validateJwtToken(String authToken) {
try {
Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
return true;
} catch (SignatureException e) {
logger.error("Invalid JWT signature: {}", e.getMessage());
} catch (MalformedJwtException e) {
logger.error("Invalid JWT token: {}", e.getMessage());
} catch (ExpiredJwtException e) {
logger.error("JWT token is expired: {}", e.getMessage());
} catch (UnsupportedJwtException e) {
logger.error("JWT token is unsupported: {}", e.getMessage());
} catch (IllegalArgumentException e) {
logger.error("JWT claims string is empty: {}", e.getMessage());
}

return false;
}
}

```

Gestion des exceptions

Nous créons maintenant la classe AuthEntryPointJwt qui implémente l'interface AuthenticationEntryPoint. Ensuite, nous remplaçons la méthode ```commence()```.

AuthEntryPointJwt.java

```java
package co.xarala.security.jwt;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

@Override
public void commence(HttpServletRequest request, HttpServletResponse response,
AuthenticationException authException) throws IOException, ServletException {
logger.error("Unauthorized error: {}", authException.getMessage());
response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error: Unauthorized");
}

}
```

### Créer les payloads pour les conterolleurs(Spring RestController)

Nous allons créer 4 agents(payloads) pour gérer les Requêtes et Reponse.

Créer un nouveau package ```payloads```.

LoginRequest.java

```java
package co.xarala.payloads;

import javax.validation.constraints.NotBlank;

public class LoginRequest {
@NotBlank
private String username;

@NotBlank
private String password;

public String getUsername() {
return username;
}

public void setUsername(String username) {
this.username = username;
}

public String getPassword() {
return password;
}

public void setPassword(String password) {
this.password = password;
}
}

```

SignupRequest.java

```java
package co.xarala.payloads;


import java.util.Set;

import javax.validation.constraints.*;

public class SignupRequest {
    @NotBlank
    @Size(min = 3, max = 20)
    private String username;

    @NotBlank
    @Size(max = 50)
    @Email
    private String email;

    private Set<String> role;

    @NotBlank
    @Size(min = 6, max = 40)
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<String> getRole() {
      return this.role;
    }

    public void setRole(Set<String> role) {
      this.role = role;
    }
}
```


JwtResponse.java

```java
package co.xarala.payloads;



import java.util.List;

public class JwtResponse {
private String token;
private String type = "Bearer";
private Long id;
private String username;
private String email;
private List<String> roles;

public JwtResponse(String accessToken, Long id, String username, String email, List<String> roles) {
this.token = accessToken;
this.id = id;
this.username = username;
this.email = email;
this.roles = roles;
}

public String getAccessToken() {
return token;
}

public void setAccessToken(String accessToken) {
this.token = accessToken;
}

public String getTokenType() {
return type;
}

public void setTokenType(String tokenType) {
this.type = tokenType;
}

public Long getId() {
return id;
}

public void setId(Long id) {
this.id = id;
}

public String getEmail() {
return email;
}

public void setEmail(String email) {
this.email = email;
}

public String getUsername() {
return username;
}

public void setUsername(String username) {
this.username = username;
}

public List<String> getRoles() {
return roles;
}
}
```

MessageResponse.java

```java
package co.xarala.payloads;


public class MessageResponse {
private String message;

public MessageResponse(String message) {
    this.message = message;
  }

public String getMessage() {
return message;
}

public void setMessage(String message) {
this.message = message;
}
}
```

### Créer un nouveau controlleur pour l'authentification(Incription et Connexion)

Créer un nouveau fichier ```AuthController``` dans le package controllers.

AuthController.java

```java
package co.xarala.controllers;


import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import co.xarala.models.ERole;
import co.xarala.models.Role;
import co.xarala.models.User;
import co.xarala.payloads.LoginRequest;
import co.xarala.payloads.SignupRequest;
import co.xarala.payloads.JwtResponse;
import co.xarala.payloads.MessageResponse;
import co.xarala.repository.RoleRepository;
import co.xarala.repository.UserRepository;
import co.xarala.security.jwt.JwtUtils;
import co.xarala.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
@Autowired
AuthenticationManager authenticationManager;

@Autowired
UserRepository userRepository;

@Autowired
RoleRepository roleRepository;

@Autowired
PasswordEncoder encoder;

@Autowired
JwtUtils jwtUtils;

@PostMapping("/signin")
public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

Authentication authentication = authenticationManager.authenticate(
new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

SecurityContextHolder.getContext().setAuthentication(authentication);
String jwt = jwtUtils.generateJwtToken(authentication);

UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
List<String> roles = userDetails.getAuthorities().stream()
.map(item -> item.getAuthority())
.collect(Collectors.toList());

return ResponseEntity.ok(new JwtResponse(jwt,
 userDetails.getId(),
 userDetails.getUsername(),
 userDetails.getEmail(),
 roles));
}

@PostMapping("/signup")
public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
if (userRepository.existsByUsername(signUpRequest.getUsername())) {
return ResponseEntity
.badRequest()
.body(new MessageResponse("Error: Username is already taken!"));
}

if (userRepository.existsByEmail(signUpRequest.getEmail())) {
return ResponseEntity
.badRequest()
.body(new MessageResponse("Error: Email is already in use!"));
}

// Create new user's account
User user = new User(signUpRequest.getUsername(),
 signUpRequest.getEmail(),
 encoder.encode(signUpRequest.getPassword()));

Set<String> strRoles = signUpRequest.getRole();
Set<Role> roles = new HashSet<>();

if (strRoles == null) {
Role userRole = roleRepository.findByName(ERole.ROLE_USER)
.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
roles.add(userRole);
} else {
strRoles.forEach(role -> {
switch (role) {
case "admin":
Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
roles.add(adminRole);

break;
case "mod":
Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
roles.add(modRole);

break;
default:
Role userRole = roleRepository.findByName(ERole.ROLE_USER)
.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
roles.add(userRole);
}
});
}

user.setRoles(roles);
userRepository.save(user);

return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
}
}

```

Vous noutez que nous avons changé, controller en controllers avec **s**.

### Ajouter les autorisations au niveau de TutorialController

Au niveau de notre fonction ```createTutorial``` nous venons d'exiger une autorisation, meme chose pour la suppression d'un tutorial.

TutorialController.java

```java
 package co.xarala.controllers;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import co.xarala.models.Tutorial;
import co.xarala.repository.TutorialRepository;



@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api")
public class TutorialController {

  @Autowired
  TutorialRepository tutorialRepository;

  @GetMapping("/tutorials")
  public ResponseEntity<List<Tutorial>> getAllTutorials(@RequestParam(required = false) String title) {
    try {
      List<Tutorial> tutorials = new ArrayList<Tutorial>();

      if (title == null)
        tutorialRepository.findAll().forEach(tutorials::add);
      else
        tutorialRepository.findByTitleContaining(title).forEach(tutorials::add);

      if (tutorials.isEmpty()) {
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
      }

      return new ResponseEntity<>(tutorials, HttpStatus.OK);
    } catch (Exception e) {
      return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @GetMapping("/tutorials/{id}")
  public ResponseEntity<Tutorial> getTutorialById(@PathVariable("id") long id) {
    Optional<Tutorial> tutorialData = tutorialRepository.findById(id);

    if (tutorialData.isPresent()) {
      return new ResponseEntity<>(tutorialData.get(), HttpStatus.OK);
    } else {
      return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }
  }

  @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")

  @PostMapping("/tutorials")
  public ResponseEntity<Tutorial> createTutorial(@RequestBody Tutorial tutorial) {
    try {
      Tutorial _tutorial = tutorialRepository
          .save(new Tutorial(tutorial.getTitle(), tutorial.getDescription(), false));
      return new ResponseEntity<>(_tutorial, HttpStatus.CREATED);
    } catch (Exception e) {
      return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @PutMapping("/tutorials/{id}")
  public ResponseEntity<Tutorial> updateTutorial(@PathVariable("id") long id, @RequestBody Tutorial tutorial) {
    Optional<Tutorial> tutorialData = tutorialRepository.findById(id);

    if (tutorialData.isPresent()) {
      Tutorial _tutorial = tutorialData.get();
      _tutorial.setTitle(tutorial.getTitle());
      _tutorial.setDescription(tutorial.getDescription());
      _tutorial.setPublished(tutorial.isPublished());
      return new ResponseEntity<>(tutorialRepository.save(_tutorial), HttpStatus.OK);
    } else {
      return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }
  }

  @PreAuthorize("hasRole('MODERATOR') or hasRole('ADMIN')")
  @DeleteMapping("/tutorials/{id}")
  public ResponseEntity<HttpStatus> deleteTutorial(@PathVariable("id") long id) {
    try {
      tutorialRepository.deleteById(id);
      return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    } catch (Exception e) {
      return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @PreAuthorize("hasRole('MODERATOR') or hasRole('ADMIN')")
  @DeleteMapping("/tutorials")
  public ResponseEntity<HttpStatus> deleteAllTutorials() {
    try {
      tutorialRepository.deleteAll();
      return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    } catch (Exception e) {
      return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }

  }


  @PreAuthorize("hasRole('MODERATOR') or hasRole('ADMIN')")
  @GetMapping("/tutorials/published")
  public ResponseEntity<List<Tutorial>> findByPublished() {
    try {
      List<Tutorial> tutorials = tutorialRepository.findByPublished(true);

      if (tutorials.isEmpty()) {
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
      }
      return new ResponseEntity<>(tutorials, HttpStatus.OK);
    } catch (Exception e) {
      return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

}
```

### Testez votre application

Ajouterz les differentes roles:

```bash
# console psql
spring_rest>
insert into roles(name) values('ROLE_USER');
insert into roles(name) values('ROLE_MODERATOR');
insert into roles(name) values('ROLE_ADMIN');
```

Utilisez Eclipse ou Maven pour lancer le projet

```bash
mvn spring-boot:run
```

Creer un nouvel utilisateur admin

```json
# http://localhost:8080/api/auth/signup

 {
  "username": "admin",
  "email": "admin@gmail.com",
  "password": "123456",
  "role": ["admin", "user"]
}
```

Se connecter

```bash
# http://localhost:8080/api/auth/signin

{
  "username": "admin",
  "password": "123456"
}
```

Le resultat

```json
{
  "id": 1,
  "username": "admin",
  "email": "admin@gmail.com",
  "roles": [
    "ROLE_ADMIN",
    "ROLE_USER"
  ],
  "accessToken": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTYyMTUyMDQxMCwiZXhwIjoxNjIxNjA2ODEwfQ.qzRk03SrUY8BZgCwu34uAWcSjsG8JO6urxV_HCydfQiExkW4Rd9BglkiW2L9HCL-9b7bdHglA_2aSiU_Du6TLQ",
  "tokenType": "Bearer"
}
```
