import superagent from "axios";
import jwt from "jsonwebtoken";
import jwkToPem from 'jwk-to-pem';

const validateToken=async (token :string, methodArn:any)=> {
    let responseBody;
    const jwkurl=`https://login.microsoftonline.com/${process.env.CLIENT_TENANT_ID}/discovery/v2.0/keys`
    let rs :any = await superagent.get(jwkurl);       
    if (rs.status != 200) {
        // if http request is failed then return error response  with appropriate status code
        rs = { msg: "Invalid token" };
        /** @type {JsonErrorObject}*/
        responseBody = {
            statusCode: 401,
            body: rs
        };
    } else {
        let sCode: number;
        let res: any;      
        const pems: any={};
        const body: any = rs.data;
        const keys = body['keys'];
        let pem;
        for (const key of keys) {
            //Convert each key to PEM
            const key_id = key.kid;
            const modulus = key.n;
            const exponent = key.e;
            const key_type = key.kty;
            const jwk = { kty: key_type, n: modulus, e: exponent };
            pem = jwkToPem(jwk);
            pems[key_id] = pem;
        }  
        //validate the token
        const decodedJwt = jwt.decode(token, { complete: true });     
        if (!decodedJwt) {  
            res = { msg: "Not a valid JWT token" };
            sCode = 401;
        }
        else {
            const kid = decodedJwt.header.kid;
            pem = kid?pems[kid]:'';
            if (!pem) {
                res = { msg: "Invalid token" };
                sCode = 401;
            }
        }
      
        jwt.verify(token, pem, function (err:any, payload:any) {
            if (err) {
                res = { msg: "Invalid token" };
                sCode = 401;                
            } else {
                sCode = 200;
                res = { msg: "Valid Token" };
            }
            responseBody = {
                statusCode: sCode,
                body:res 
            }; 
        });
        
    }
    return responseBody;
}

exports.handler = async (event:any, callback:any) => {  
    let verifyTokenResponse;
    let authResponse :any;
    let errMsg;
    try {
        verifyTokenResponse = await validateToken(event.authorizationToken, event.methodArn);        
        switch (verifyTokenResponse?.body?.msg) {
            case 'Not a valid JWT token':
                errMsg = 'Not a valid JWT token';
                break;
            case 'Invalid token':
                errMsg = 'Unauthorized';
                authResponse = {
                    "principalId": "user",
                    "policyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Action": "execute-api:Invoke",
                                "Effect": "deny",
                                "Resource": "*"
                            }
                        ]
                    }
                };                
                
                authResponse.context = {
                    "customErrorMessage": errMsg,
                };
                break;
            case 'Valid Token':
                authResponse = {
                    "principalId": "user",
                    "policyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Action": "execute-api:Invoke",
                                "Effect": "Allow",
                                "Resource": "*"
                            }
                        ]
                    }
                };
                errMsg = null;
                break;
            default:
                errMsg = "Error: Invalid token";
        }
    }
    catch (exception) {
        console.log("Error ::: ", exception);
        errMsg = "Error: Internal server error";

    }
   return authResponse;
};

