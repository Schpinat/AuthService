package net.absoft;

import org.testng.annotations.DataProvider;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.absoft.data.Response;
import net.absoft.services.AuthenticationService;
import org.testng.annotations.*;
import org.testng.asserts.SoftAssert;

import static org.testng.Assert.*;

public class AuthenticationServiceTest {

  @BeforeMethod
  public void setUp() {
    System.out.println(" setup");
  }
  @Test (groups = "positive"
  )
  public void testFail(){
    fail("FAILING TEST");
  }
  @Test (
          description = "Test Successful Authentication",
          groups = "positive"
  )
  @Parameters ({"email-address", "password"})
  public void testSuccessfulAuthentication(String email, String password) {
    SoftAssert sa = new SoftAssert();
    Response response = new AuthenticationService().authenticate(email, password);
    sa.assertEquals(response.getCode(), 200, "Response code should be 200");
    sa.assertTrue(validateToken(response.getMessage()),
        "Token should be the 32 digits string. Got: " + response.getMessage());
    System.out.println("testSuccessfulAuthentication");
    sa.assertAll();
  }
  @DataProvider(name = "invalidAuthentication", parallel = true)
  public Object[][] invalidAuthentication () {
    return new Object[][]{
            {"user1@test.com", "wrong_password1", new Response(401, "Invalid email or password")},
            {"", "password1", new Response(400, "Email should not be empty string")},
            {"user1", "password1", new Response(400, "Invalid email")},
            {"user1@test", "", new Response(400, "Password should not be empty string")},
    };
  }

  @Test (
          groups = "negative",
          dataProvider = "invalidAuthentication"
  )
  public void testInvalidAuthentication (String email, String password, Response expectedResponse) {
    Response actualResponse= new AuthenticationService()
            .authenticate(email, password);
    assertEquals(actualResponse.getCode(), expectedResponse.getCode(), "Unexpected response");
    assertEquals(actualResponse.getMessage(), expectedResponse.getMessage(),
        "Response message should be \"Invalid email or password\"");
  }
    @Test
    public void testAuthenticationWithWrongPassword() {
        Response response = new AuthenticationService()
                .authenticate("user1@test.com", "wrong_password1");
        assertEquals(response.getCode(), 401, "Response code should be 401");
        assertEquals(response.getMessage(), "Invalid email or password",
                "Response message should be \"Invalid email or password\"");
    }

  @Test (
          groups = "negative"
  )
  public void testAuthenticationWithEmptyEmail() {
    Response response = new AuthenticationService().authenticate("", "password1");
    assertEquals(response.getCode(), 400, "Response code should be 400");
    assertEquals(response.getMessage(), "Email should not be empty string",
        "Response message should be \"Email should not be empty string\"");
  }

  @Test (
          groups = "negative"
  )
  public void testAuthenticationWithInvalidEmail() {
    Response response = new AuthenticationService()
            .authenticate("user1", "password1");
    assertEquals(response.getCode(), 400, "Response code should be 200");
    assertEquals(response.getMessage(), "Invalid email",
        "Response message should be \"Invalid email\"");
  }

  @Test (
          groups = "negative"
  )
  public void testAuthenticationWithEmptyPassword() {
    Response response = new AuthenticationService()
            .authenticate("user1@test", "");
    assertEquals(response.getCode(), 400, "Response code should be 400");
    assertEquals(response.getMessage(), "Password should not be empty string",
        "Response message should be \"Password should not be empty string\"");
  }

  private boolean validateToken(String token) {
    final Pattern pattern = Pattern.compile("\\S{32}", Pattern.MULTILINE);
    final Matcher matcher = pattern.matcher(token);
    return matcher.matches();
  }
}
