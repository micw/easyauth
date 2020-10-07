package de.wyraz.easyauth.provider;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import de.wyraz.easyauth.provider.internal.StaticUserProvider;
import de.wyraz.easyauth.provider.ldap.LdapUserProvider;

@Configuration
@ConfigurationProperties
public class UserProviderFactory {
	
	@Bean
	public IUserProvider getUserProvider(@Value("${userProvider}") String userProvider) throws Exception {
		if ("ldap".equals(userProvider)) {
			return new LdapUserProvider();
		}
		if ("static".equals(userProvider)) {
			return new StaticUserProvider();
		}
		return (IUserProvider) Class.forName(userProvider).getDeclaredConstructor().newInstance();
	}

}
