//const axios = require('axios');
//const winston = require('winston');
//const axios = require('axios'); // npm install axios
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { Readable, Writable } = require('stream');

const LoginType = {
  OTCS_TICKET: 'OTCS_TICKET',
  OTDS_TICKET: 'OTDS_TICKET',
  OTDS_BEARER: 'OTDS_BEARER'
};

const LogType = {
  INFO:  'INFO',
  DEBUG: 'DEBUG'
};

class LoginTimeoutException extends Error {}

/**
 * Content Server Rest API class - do Login and get OTCSTicket, OTDSTicket or Bearer Token and do calls
 */
class CSRestAPI {
  _logger;
  _userAgent = 'Chrome xECM';
  _baseUrl = '';
  _ticket = '';
  _usr = '';
  _pwd = '';
  _verifySSL = true;
  _loginType;
  _volumesHash = {};
  _categoryHash = {};

  /**
   * Constructor
   * 
   * @param {LoginType} loginType 
   * @param {string} loginUrl 
   * @param {string} userOrClientId 
   * @param {string} pwOrClientSecret 
   * @param {boolean} verifySSL 
   * @param {LoginType} logger 
   */
  constructor(loginType, loginUrl, userOrClientId, pwOrClientSecret, verifySSL, logger) {
    try {
        this._logger = logger || null;
        this._verifySSL = verifySSL;
        this._loginType = loginType;
        this._baseUrlDict = this._checkUrl(loginUrl);
        this._usr = userOrClientId;
        this._pwd = pwOrClientSecret;
    } catch (err) {
        const errorMessage = `XECMLogin Error during init: ${err.message}`;
        console.error(errorMessage);
        throw new Error(errorMessage);
    }
  }

  /**
   * Do HTTPS Call
   * 
   * @param {string} postData 
   * @param {object} options object containing the request information
   * @returns {object} with structure { 'statusCode': 200, 'body': 'result string' }
   */
  doCallHttps = (postData, options) => {
    // switch off SSL certificate check
    if (!this._verifySSL) {
      options['rejectUnauthorized'] = false;
      options['requestCert'] = true;
      options['agent'] = false;
    }

    return new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        //let body = "";
        let body = Buffer.from("");
        //res.setEncoding('utf8');
        res.on("data", (chunk) => {
          body = Buffer.concat([body, Buffer.from(chunk)]);
          //body += chunk;
        });
        res.on("end", () => {
          resolve({
            statusCode: res.statusCode,
            body: body
          });
        });
      });

      req.on("error", (err) => {
        reject(err);
      });

      if (this._logger === LogType.DEBUG) {
        req.on('socket', function (socket) {
            //let buf = Buffer.from("");
            //buf = Buffer.concat([buf, Buffer.from("========\nRequest\n========")]);
            console.log("========\nRequest\n========")
            if(socket._httpMessage && socket._httpMessage.outputData && socket._httpMessage.outputData.length > 0) {
              for(let i=0; i<socket._httpMessage.outputData.length; i++) {
                let d = socket._httpMessage.outputData[i];
                if(d['data'] && !d['type']) {
                  //buf = Buffer.concat([buf, Buffer.from(d['data'])]);
                  console.log(d['data'].toString('utf8'));
                }
              }
            }
            console.log("========\nResponse\n========");
            socket.on('data', function (data) {
              //buf = Buffer.concat([buf, data]);
              //fs.writeFileSync('/home/fitsch/Downloads/log.txt', buf);
              console.log(data.toString('utf8'));
            });
        });
      }

      if (postData) {
          req.write(postData);
      }
      req.end();
    });
  }

  /**
   * Do HTTP Call
   * 
   * @param {string} postData 
   * @param {object} options object containing the request information
   * @returns {object} with structure { 'statusCode': 200, 'body': 'result string' }
   */
  doCallHttp = (postData, options) => {
    return new Promise((resolve, reject) => {
      const req = http.request(options, (res) => {
        //let body = "";
        let body = Buffer.from("");
        //res.setEncoding('utf8');
        res.on("data", (chunk) => {
          body = Buffer.concat([body, Buffer.from(chunk)]);
          //body += chunk;
        });
        res.on("end", () => {
          resolve({
            statusCode: res.statusCode,
            body: body
          });
        });
      });

      req.on("error", (err) => {
        reject(err);
      });

      if (this._logger === LogType.DEBUG) {
        req.on('socket', function (socket) {
            //let buf = Buffer.from("");
            //buf = Buffer.concat([buf, Buffer.from("========\nRequest\n========")]);
            console.log("========\nRequest\n========")
            if(socket._httpMessage && socket._httpMessage.outputData && socket._httpMessage.outputData.length > 0) {
              for(let i=0; i<socket._httpMessage.outputData.length; i++) {
                let d = socket._httpMessage.outputData[i];
                if(d['data'] && !d['type']) {
                  //buf = Buffer.concat([buf, Buffer.from(d['data'])]);
                  console.log(d['data'].toString('utf8'));
                }
              }
            }
            console.log("========\nResponse\n========");
            socket.on('data', function (data) {
              //buf = Buffer.concat([buf, data]);
              //fs.writeFileSync('/home/fitsch/Downloads/log.txt', buf);
              console.log(data.toString('utf8'));
            });
        });
      }

      if (postData) {
          req.write(postData);
      }
      req.end();
    });
  }

  /**
   * Download File to Stream
   * 
   * @param {Stream} fileStream file stream (write)
   * @param {object} options object containing the request information
   * @returns {object} with structure { 'statusCode': 200, 'body': '<filePath>' }
   */
  doDownloadHttps = (fileStream, options) => {
    return new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        if (res.statusCode === 200) {
          res.pipe(fileStream)
              .on('error', reject)
              .once('close', () => resolve({
            statusCode: res.statusCode,
            body: 'file successfully downloaded'
          }));
        } else {
          // Consume response data to free up memory
          res.resume();
          reject(new Error(`Request Failed With a Status Code: ${res.statusCode}`));
        }
      });

      req.on("error", (err) => {
        reject(err);
      });

      if (this._logger === LogType.DEBUG) {
        req.on('socket', function (socket) {
            console.log("========\nRequest\n========")
            if(socket._httpMessage && socket._httpMessage.outputData && socket._httpMessage.outputData.length > 0) {
              for(let i=0; i<socket._httpMessage.outputData.length; i++) {
                let d = socket._httpMessage.outputData[i];
                if(d['data'] && !d['type']) {
                  console.log(d['data'].toString('utf8'));
                }
              }
            }
            console.log("========\nResponse\n========");
            socket.on('data', function (data) { console.log(data.toString('utf8')); });
        });
      }

      req.end();
    });
  }

  /**
   * Download File to Stream
   * 
   * @param {Stream} fileStream file stream (write)
   * @param {object} options object containing the request information
   * @returns {object} with structure { 'statusCode': 200, 'body': '<filePath>' }
   */
  doDownloadHttp = (fileStream, options) => {
    return new Promise((resolve, reject) => {
      const req = http.request(options, (res) => {
        if (res.statusCode === 200) {
          res.pipe(fileStream)
              .on('error', reject)
              .once('close', () => resolve({
            statusCode: res.statusCode,
            body: 'file successfully downloaded'
          }));
        } else {
          // Consume response data to free up memory
          res.resume();
          reject(new Error(`Request Failed With a Status Code: ${res.statusCode}`));
        }
      });

      req.on("error", (err) => {
        reject(err);
      });

      if (this._logger === LogType.DEBUG) {
        req.on('socket', function (socket) {
            console.log("========\nRequest\n========")
            if(socket._httpMessage && socket._httpMessage.outputData && socket._httpMessage.outputData.length > 0) {
              for(let i=0; i<socket._httpMessage.outputData.length; i++) {
                let d = socket._httpMessage.outputData[i];
                if(d['data'] && !d['type']) {
                  console.log(d['data'].toString('utf8'));
                }
              }
            }
            console.log("========\nResponse\n========");
            socket.on('data', function (data) { console.log(data.toString('utf8')); });
        });
      }

      req.end();
    });
  }

  /**
   * Upload File from Stream
   * 
   * @param {Stream} fileStream file stream (read)
   * @param {number} fileLength length of file
   * @param {string} fileParamName parameter name of file
   * @param {string} remoteFileName file name in target system
   * @param {string} mimeType mime type of the file i.e. application/octet-stream
   * @param {string} boundary boundary string for multipart upload i.e. --1752596654665
   * @param {Buffer} additionalFormData 
   * @param {object} options object containing the request information
   * @returns {object} with structure { 'statusCode': 200, 'body': Buffer }
   */
  doUploadHttps = (fileStream, fileLength, fileParamName, remoteFileName, mimeType, boundary, additionalFormData, options) => {
    // switch off SSL certificate check
    if (!this._verifySSL) {
      options['rejectUnauthorized'] = false;
      options['requestCert'] = true;
      options['agent'] = false;
    }

    return new Promise((resolve, reject) => {
      const crlf = Buffer.from(`\r\n`);
      const preamble = Buffer.from(
        `--${boundary}${crlf}` +
        `Content-Disposition: form-data; name="${fileParamName}"; filename="${remoteFileName}"${crlf}` +
        `Content-Type: ${mimeType}${crlf}${crlf}`
      );
      const postamble = Buffer.from(`${crlf}--${boundary}--${crlf}`);

      if (additionalFormData.length > 0) {
        options['headers']['Content-Length'] = preamble.length + fileLength + crlf.length + additionalFormData.length;
      } else {
        options['headers']['Content-Length'] = preamble.length + fileLength + postamble.length;
      }

      const req = https.request(options, (res) => {
        let body = Buffer.from("");
        //res.setEncoding('utf8');
        res.on("data", (chunk) => {
          body = Buffer.concat([body, Buffer.from(chunk)]);
          //body += chunk;
        });
        res.on("end", () => {
          resolve({
            statusCode: res.statusCode,
            body: body
          });
        });
      });

      req.on("error", (err) => {
        reject(err);
      });

      if (this._logger === LogType.DEBUG) {
        req.on('socket', function (socket) {
            console.log("========\nRequest\n========")
            if(socket._httpMessage && socket._httpMessage.outputData && socket._httpMessage.outputData.length > 0) {
              for(let i=0; i<socket._httpMessage.outputData.length; i++) {
                let d = socket._httpMessage.outputData[i];
                if(d['data'] && !d['type']) {
                  console.log(d['data'].toString('utf8'));
                }
              }
            }
            console.log("========\nResponse\n========");
            socket.on('data', function (data) { console.log(data.toString('utf8')); });
        });
      }

      // Write preamble
      req.write(preamble);

      // Pipe file stream
      fileStream.pipe(req, { end: false });

      fileStream.on('end', () => {
        // Write postamble and end request
        if (additionalFormData.length > 0) {
          req.end(crlf + additionalFormData);
        } else {
          req.end(postamble);
        }
      });    
    });
  }

  /**
   * Upload File directly from Stream
   * 
   * @param {Stream} fileStream file stream (read)
   * @param {number} fileLength length of file
   * @param {string} fileParamName parameter name of file
   * @param {string} remoteFileName file name in target system
   * @param {string} mimeType mime type of the file i.e. application/octet-stream
   * @param {string} boundary boundary string for multipart upload i.e. --1752596654665
   * @param {Buffer} additionalFormData addtional formdata
   * @param {object} options object containing the request information
   * @returns {object} with structure { 'statusCode': 200, 'body': Buffer }
   */
  doUploadHttp = (fileStream, fileLength, fileParamName, remoteFileName, mimeType, boundary, additionalFormData, options) => {
    return new Promise((resolve, reject) => {
      const crlf = Buffer.from(`\r\n`);
      const preamble = Buffer.from(
        `--${boundary}${crlf}` +
        `Content-Disposition: form-data; name="${fileParamName}"; filename="${remoteFileName}"${crlf}` +
        `Content-Type: ${mimeType}${crlf}${crlf}`
      );
      const postamble = Buffer.from(`${crlf}--${boundary}--${crlf}`);

      if (additionalFormData.length > 0) {
        options['headers']['Content-Length'] = preamble.length + fileLength + crlf.length + additionalFormData.length;
      } else {
        options['headers']['Content-Length'] = preamble.length + fileLength + postamble.length;
      }

      const req = http.request(options, (res) => {
        let body = Buffer.from("");
        //res.setEncoding('utf8');
        res.on("data", (chunk) => {
          body = Buffer.concat([body, Buffer.from(chunk)]);
          //body += chunk;
        });
        res.on("end", () => {
          resolve({
            statusCode: res.statusCode,
            body: body
          });
        });
      });

      req.on("error", (err) => {
        reject(err);
      });

      if (this._logger === LogType.DEBUG) {
        req.on('socket', function (socket) {
            console.log("========\nRequest\n========")
            if(socket._httpMessage && socket._httpMessage.outputData && socket._httpMessage.outputData.length > 0) {
              for(let i=0; i<socket._httpMessage.outputData.length; i++) {
                let d = socket._httpMessage.outputData[i];
                if(d['data'] && !d['type']) {
                  console.log(d['data'].toString('utf8'));
                }
              }
            }
            console.log("========\nResponse\n========");
            socket.on('data', function (data) { console.log(data.toString('utf8')); });
        });
      }

      // Write preamble
      req.write(preamble);

      // Pipe file stream
      fileStream.pipe(req, { end: false });

      fileStream.on('end', () => {
        // Write postamble and end request
        if (additionalFormData.length > 0) {
          req.end(crlf + additionalFormData);
        } else {
          req.end(postamble);
        }
      });    
    });
  }

  /**
   * Do Login - set this._ticket
   */
  doLogin = async() => {
    try {
      if (this._loginType === LoginType.OTCS_TICKET) {
          if (this._logger === LogType.INFO || this._logger === LogType.DEBUG) {
            console.info('Create OTCSTicket with username and password.');
          }
          this._ticket = await this._otcsLogin(this._usr, this._pwd);
          if (this._logger === LogType.INFO || this._logger === LogType.DEBUG) {
            console.info('OTCSTicket created.');
          }
      } else if (this._loginType === LoginType.OTDS_TICKET) {
          if (this._logger === LogType.INFO || this._logger === LogType.DEBUG) {
            console.info('Create OTDSTicket with username and password.');
          }
          this._ticket = await this._otdsLogin(this._usr, this._pwd);
          if (this._logger === LogType.INFO || this._logger === LogType.DEBUG) {
            console.info('OTDSTicket created.');
          }
      } else {
          if (this._logger === LogType.INFO || this._logger === LogType.DEBUG) {
            console.info('Create Bearer Token in OTDS with client_id and client_secret.');
          }
          this._ticket = await this._otdsToken(this._usr, this._pwd);
          if (this._logger === LogType.INFO || this._logger === LogType.DEBUG) {
            console.info('Bearer Token created.');
          }
      }

      console.info(`XECMLogin successful: ${this._ticket}`);
    } catch (err) {
        const errorMessage = `XECMLogin Error during init: ${err.message}`;
        console.error(errorMessage);
        throw new Error(errorMessage);
    }

  }

  /**
   * Get OTCSTicket
   * 
   * @param {string} username credential username
   * @param {string} password credential password
   * @returns {string} OTCSTicket
   */
  _otcsLogin = async(username, password) => {
    let error_message = "";
    let otcsticket = "";
    let apiendpoint = "api/v1/auth";
    try {
      let params = { "username": username, "password": password };
      let post_data = this._getUrlEncodedData(params);
      let options = {
          hostname: this._baseUrlDict['host'],
          port: this._baseUrlDict['port'],
          path: this._baseUrlDict['path'] + apiendpoint,
          method: 'POST',
          headers: {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': post_data.length
          }
      };

      let res = "";
      if (this._baseUrlDict['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const resObj = JSON.parse(res['body'].toString("utf8"));
        otcsticket = resObj['ticket'];
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      error_message = `Login Error on ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
      console.error(error_message);
      throw new Error(error_message);
    }
    return otcsticket;
  }


  /**
   * Get OTDSTicket
   * 
   * @param {string} username credential username
   * @param {string} password credential password
   * @returns {string} OTCSTicket
   */
  _otdsLogin = async(username, password) => {
    let error_message = "";
    let otdsticket = "";
    let apiendpoint = "otdsws/v1/authentication/credentials";
    try {
      let params = { "user_name": username, "password": password };
      let post_data = this._getJsonRawData(params);
      let options = {
          hostname: this._baseUrlDict['host'],
          port: this._baseUrlDict['port'],
          path: this._baseUrlDict['path'] + apiendpoint,
          method: 'POST',
          headers: {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json;charset=utf-8',
            'Content-Length': post_data.length
          }
      };

      let res = "";
      if (this._baseUrlDict['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const resObj = JSON.parse(res['body'].toString("utf8"));
        otdsticket = resObj['ticket'];
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      error_message = `Login Error on ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
      console.error(error_message);
      throw new Error(error_message);
    }
    return otdsticket;
  }

  /**
   * Get Bearer Token from OTDS
   * 
   * @param {string} clientId client id of the OTDS oAuth2 client
   * @param {string} clientSecret client secret of the OTDS oAuth2 client
   * @returns {string} Bearer Token
   */
  _otdsToken = async(clientId, clientSecret) => {
    let error_message = "";
    let bearertoken = "";
    let apiendpoint = "otdsws/oauth2/token";
    try {
      let params = { "grant_type": "client_credentials", "requested_token_type": "urn:ietf:params:oauth:token-type:access_token" };
      let post_data = this._getUrlEncodedData(params);
      let options = {
          hostname: this._baseUrlDict['host'],
          port: this._baseUrlDict['port'],
          path: this._baseUrlDict['path'] + apiendpoint,
          method: 'POST',
          headers: {
            'Authorization': 'Basic ' + Buffer.from(clientId + ':' + clientSecret, "utf-8").toString('base64'),
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': post_data.length
          }
      };

      let res = "";
      if (this._baseUrlDict['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const resObj = JSON.parse(res['body'].toString("utf8"));
        bearertoken = resObj['access_token'];
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      error_message = `Login Error on ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
      console.error(error_message);
      throw new Error(error_message);
    }
    return bearertoken;
  }

  /**
   * 
   * @param {object} req_header header object
   * @returns {object} return changed header object
   */
  _addAuthHeader = (req_header) => {
    let auth_header = ''
    let auth_ticket = ''
    if (this._loginType === LoginType.OTCS_TICKET) {
      auth_header = 'OTCSTicket';
      auth_ticket = this._ticket;
    } else if(this._loginType === LoginType.OTDS_TICKET) {
      auth_header = 'OTDSTicket';
      auth_ticket = this._ticket;
    } else {
      auth_header = 'Authorization';
      auth_ticket = 'Bearer ' + this._ticket;
    }

    req_header[auth_header] = auth_ticket;
    return req_header;
  }

  /**
   * Check URL to ensure it ends with "/" and return an URL object
   *
   * @param {string} url URL to be checked
   * @returns {object} Object with structure { protocol: "", host: "", port: 0, path: "" }
   */
  _checkUrl(url) {
    let ret_val = { protocol: "", host: "", port: 0, path: "" };
    let checked_url = url.endsWith('/') ? url : url + '/';
    let part_hostname = "";

    if (checked_url.startsWith("http://")) {
      ret_val['protocol'] = "http";
      ret_val['port'] = 80;
      part_hostname = checked_url.substring(7);
    } else if(checked_url.startsWith("https://")) {
      ret_val['protocol'] = "https";
      ret_val['port'] = 443;
      part_hostname = checked_url.substring(8);
    } else {
      throw new Error(`Protocol used in URL is not supported. Must be http or https: ${url}`)
    }

    let parts = part_hostname.split("/");
    if (parts.length < 1 || !parts[0]) {
      throw new Error(`Malformed URL. Hostname not found: ${url}`)
    }

    let hostname = parts[0];
    if (hostname.includes(":")) {
      ret_val['host'] = hostname.substring(0, hostname.indexOf(":"));
      let port = parseInt(hostname.substring(hostname.indexOf(":")+1));
      if (!port) {
        throw new Error(`Malformed Port. It must be a number: ${url}`);
      }
      ret_val['port'] = parseInt(hostname.substring(hostname.indexOf(":")+1));
    } else {
      ret_val['host'] = hostname;
    }

    let path = "/";
    if (parts.length > 1) {
      for(let i=1; i<parts.length; i++) {
        if (parts[i]) {
          path += parts[i] + "/";
        }
      }
    }

    ret_val['path'] = path;

    return ret_val;
  }

  /**
   * Get URL encoded data string for application/x-www-form-urlencoded post
   *
   * @param {object} params object containing URL parameters { 'param': 'val' }
   * @returns {string} URL encoded data string
   */
  _getUrlEncodedData(params) {
    let ret_val = "";
    let cnt = 0;

    for (const [key, value] of Object.entries(params)) {
      if (typeof value === "object") {
        value.forEach(element => {
          if (cnt > 0) {
            ret_val += "&";
          }
          ret_val += `${key}=${encodeURIComponent(element)}`;
          cnt ++;
        });
      } else {
        if (cnt > 0) {
          ret_val += "&";
        }
        ret_val += `${key}=${encodeURIComponent(value)}`;
      }
      cnt++;
    }
    return ret_val;
  }

  /**
   * Get multipart/form-data object
   * 
   * @param {object} params object containing parameters { 'param': 'val' }
   * @param {Array} files list containing files [{ 'param': 'file1', 'filename': 'test.jpg', 'mimetype': 'image/jpeg', 'data': fs.readFileSync(...) }, ...]
   * @returns {object} Form-Data object with structure { 'boundary': '1344552345', 'formdata': Buffer} - print out with obj['formdata'].toString('utf8')
   */
  _getFormData(params, files) {
    let crlf = "\r\n";
    let boundaryKey = new Date().getTime(); //Math.random().toString(16);
    let boundary = `--${boundaryKey}`;
    let startDelimiter = `--${boundary}`;
    let delimiter = `${crlf}--${boundary}`;
    let closeDelimiter = `${delimiter}--`;

    let ret_val = { 'boundary': boundary, 'formdata': '' };
    let cnt = 0;

    let buf = Buffer.from("", "utf8");

    // data = fs.readFileSync("./test.jpg");
    // 'Content-Disposition: form-data; name="fileToUpload"; filename="test.jpg"' + crlf
    // 'Content-Type: image/jpeg' + crlf + crlf
    // application/octet-stream
    // data

    if (files && files.length > 0) {
      for (let i=0; i<files.length; i++) {
        if (files[i]['mimetype']) {
          if (cnt === 0) {
            buf = Buffer.concat([buf, Buffer.from(`${startDelimiter}${crlf}Content-Disposition: form-data; name="${files[i]['param']}"; filename="${files[i]['filename']}"${crlf}Content-Type: ${files[i]['mimetype']}${crlf}${crlf}`, "utf8"), files[i]['data']]);
          } else {
            buf = Buffer.concat([buf, Buffer.from(`${delimiter}${crlf}Content-Disposition: form-data; name="${files[i]['param']}"; filename="${files[i]['filename']}"${crlf}Content-Type: ${files[i]['mimetype']}${crlf}${crlf}`, "utf8"), files[i]['data']]);
          }
        } else {
          if (cnt === 0) {
            buf = Buffer.concat([buf, Buffer.from(`${startDelimiter}${crlf}Content-Disposition: form-data; name="${files[i]['param']}"; filename="${files[i]['filename']}"${crlf}Content-Type: application/octet-stream${crlf}${crlf}`, "utf8"), files[i]['data']]);
          } else {
            buf = Buffer.concat([buf, Buffer.from(`${delimiter}${crlf}Content-Disposition: form-data; name="${files[i]['param']}"; filename="${files[i]['filename']}"${crlf}Content-Type: application/octet-stream${crlf}${crlf}`, "utf8"), files[i]['data']]);
          }
        }
        cnt++;
      }
    }

    for (const [key, value] of Object.entries(params)) {
      if (typeof value === "object") {
        value.forEach(element => {
          if (cnt === 0) {
            buf = Buffer.concat([buf, Buffer.from(`${startDelimiter}${crlf}Content-Disposition: form-data; name="${key}"${crlf}${crlf}${element}`, "utf8")]);
          } else {
            buf = Buffer.concat([buf, Buffer.from(`${delimiter}${crlf}Content-Disposition: form-data; name="${key}"${crlf}${crlf}${element}`, "utf8")]);
          }
          cnt++;
        });
      } else {
        if (cnt === 0) {
          buf = Buffer.concat([buf, Buffer.from(`${startDelimiter}${crlf}Content-Disposition: form-data; name="${key}"${crlf}${crlf}${value}`, "utf8")]);
        } else {
          buf = Buffer.concat([buf, Buffer.from(`${delimiter}${crlf}Content-Disposition: form-data; name="${key}"${crlf}${crlf}${value}`, "utf8")]);
        }
      }
      cnt++;
    }

    if (cnt > 0) {
      buf = Buffer.concat([buf, Buffer.from(closeDelimiter, "utf8")]);
      ret_val['formdata'] = buf;
    }

    return ret_val;
  }

  /**
   * Get JSON data string for application/json post
   *
   * @param {object} params object containing raw data
   * @returns {string} JSON data string
   */
  _getJsonRawData(params) {
    return JSON.stringify(params);
  }

  /**
   * Ping Content Server API with GET method.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @returns {object} Result of API call. I.e. {'rest_api': [{'build': 2, 'href': 'api/v1', 'version': 1}]}
   */
  ping = async(baseUrlCS) => {
    let error_message = "";
    let retval = {};
    let apiendpoint = "api/v1/ping";
    try {
      let options = {
          hostname: this._baseUrlDict['host'],
          port: this._baseUrlDict['port'],
          path: this._baseUrlDict['path'] + apiendpoint,
          method: 'GET',
          headers: {
            'User-Agent': this._userAgent
          }
      };

      let res = "";
      if (this._baseUrlDict['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        retval = JSON.parse(res['body'].toString("utf8"));
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      error_message = `Error in ping() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
      console.error(error_message);
      throw new Error(error_message);
    }
    return retval;
  }

  /**
   * Get Node Information - optionally include property filter, load category information, load permissions, load classifications.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Node ID to get the information
   * @param {Array} filterProperties The List to fetch only certain properties. I.e. ['id', 'name'] or ['id', 'name', 'type', 'type_name', 'name_multilingual', 'description_multilingual'] or [] for all properties
   * @param {boolean} loadCategories Optionally load categories of node.
   * @param {boolean} loadPermissions Optionally load permissions of node.
   * @param {boolean} loadClassifications Optionally load classifications of node.
   * @returns {object} node information with structure: { 'properties': {}, 'categories': [], 'permissions': [], 'classifications': []}
   */
  node_get = async(baseUrlCS, nodeId, filterProperties, loadCategories, loadPermissions, loadClassifications) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_get() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, filterProperties=${filterProperties}, loadCategories=${loadCategories}, loadPermissions=${loadPermissions}, loadClassifications=${loadClassifications}`);
    }

    let retval = { 'properties': {}, 'categories': [], 'permissions': { 'owner': {}, 'group': {}, 'public': {}, 'custom': [] }, 'classifications': []};
    let apiendpoint = `api/v2/nodes/${nodeId}`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = {};
      if (filterProperties && filterProperties.length > 0) {
        if (!params.hasOwnProperty('fields')) {
          params['fields'] = [];
        }
        let param = 'properties{' + filterProperties.join(',') + '}';
        params['fields'].push(param);
      }

      if (loadCategories) {
        if (!params.hasOwnProperty('fields')) {
          params['fields'] = [];
        }
        let param = 'categories';
        params['fields'].push(param);
      }

      if (loadPermissions) {
        if (!params.hasOwnProperty('fields')) {
          params['fields'] = [];
        }
        let param = 'permissions';
        params['fields'].push(param);

        if (!params.hasOwnProperty('expand')) {
          params['expand'] = [];
        }
        params['expand'].push('permissions{right_id}');
      }

      let get_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint + ('?' + get_data) || '',
          method: 'GET',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          const item = jres['results'];
          if(item['data'] && item['data']['properties']) {
            retval['properties'] = item['data']['properties'];

            if (loadCategories) {
              retval['categories'] = item['data']['categories'];
            }

            if (loadPermissions && item['data']['permissions'] && item['data']['permissions'].length > 0) {
              for(let i=0; i<item['data']['permissions'].length; i++) {
                const perms = item['data']['permissions'][i];
                if (perms['type'] === 'owner') {
                  retval['permissions']['owner'] = perms;
                } else if(perms['type'] === 'group') {
                  retval['permissions']['group'] = perms;
                } else if(perms['type'] === 'public') {
                  retval['permissions']['public'] = perms;
                } else if(perms['type'] === 'custom') {
                  retval['permissions']['custom'].push(perms);
                } else {
                  throw new Error(`Error in node_get() - permission type ${perms['type']} is not supported.`);
                }
              }
            }

            if (loadClassifications) {
              try {
                retval['classifications'] = await this.node_classifications_get(baseUrlCS, nodeId, ['data']);
              } catch(itemError) {
                let error_message = `Error in node_get() while getting classifications -> ${itemError}`;
                console.error(error_message);
              }
            }
          }
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_get() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_get() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Create a Node.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} parentId The parent id of container in which the node is created.
   * @param {number} typeId The type id of the new node. I.e. 0 for a folder
   * @param {string} nodeName The name of the new node.
   * @param {string} nodeDescription The description of the new node.
   * @param {object} multiNames The names in different languages of the new node. I.e. { 'en': 'name en', 'de': 'name de' }
   * @param {object} multiDescriptions The descriptions in different languages of the new node. I.e. { 'en': 'desc en', 'de': 'desc de' }
   * @returns {number} the new node id of the uploaded document
   */
  node_create = async(baseUrlCS, parentId, typeId, nodeName, nodeDescription, multiNames, multiDescriptions) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_create() start: baseUrlCS=${baseUrlCS}, parentId=${parentId}, typeId=${typeId}, nodeName=${nodeName}, nodeDescription=${nodeDescription}, multiNames=${JSON.stringify(multiNames)}, multiDescriptions=${JSON.stringify(multiDescriptions)}`);
    }

    let retval = -1;
    let apiendpoint = `api/v2/nodes`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let data = {'type': typeId, 'parent_id': parentId, 'name': nodeName};

      if (nodeDescription) {
        data['description'] = nodeDescription;
      }
      if (multiNames) {
        data['name_multilingual'] = multiNames;
      }
      if (multiDescriptions) {
        data['description_multilingual'] = multiDescriptions;
      }

      let params = { 'body': JSON.stringify(data) };
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'POST',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results') && jres['results'].hasOwnProperty('data')) {
          const item = jres['results']['data'];
          if(item['properties']) {
            retval = item['properties']['id'];
          }
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_create() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_create() finished: ${retval}`);
    }
    return retval;
  }

  /**
   * Generic update of a Node.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} parentId The node which is updated.
   * @param {number} newParentId Optional: if set then the node is moved to this new target.
   * @param {string} newName Optional: if set then the name of the node is renamed.
   * @param {string} newDescription Optional: if set then the description of the node is changed.
   * @param {object} newMultiNames Optional: if set then the names in different languages of the node are renamed. I.e. { 'en': 'name en', 'de': 'name de' }
   * @param {object} newMultiDescriptions Optional: if set then the descriptions in different languages of the node are changed. I.e. { 'en': 'desc en', 'de': 'desc de' }
   * @param {object} newCategoriesWhenMoved Optional: if set then the categories of the node are changed when the node is moved to a new location. I.e. {"6228_2":"hello"} or {"inheritance":0} (selecting ORIGINAL categories inheritance when moved) or {"inheritance":1, "6228_2":"hello"} (selecting DESTINATION categories inheritance and applying a custom value to 6228_2 when moved) or {"inheritance":2, "9830_1":{}, "6228_1":{}} (selecting MERGED categories inheritance and applying default values to 9830_1 and 6228_1)
   * @returns {number} the node id of the updated node
   */
  node_update = async(baseUrlCS, nodeId, newParentId, newName, newDescription, newMultiNames, newMultiDescriptions, newCategoriesWhenMoved) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_update() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, newParentId=${newParentId}, newName=${newName}, newDescription=${newDescription}, newMultiNames=${JSON.stringify(newMultiNames)}, newMultiDescriptions=${JSON.stringify(newMultiDescriptions)}, newCategoriesWhenMoved=${JSON.stringify(newCategoriesWhenMoved)}`);
    }

    let retval = -1;
    let apiendpoint = `api/v2/nodes/${nodeId}`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let data = {};

      if (newParentId && newParentId > 0) {
        data['parent_id'] = newParentId;
      }

      if (newName) {
        data['name'] = newName;
      }

      if (newDescription) {
        data['description'] = newDescription;
      }

      if (newMultiNames) {
        data['name_multilingual'] = newMultiNames;
      }

      if (newMultiDescriptions) {
        data['description_multilingual'] = newMultiDescriptions;
      }

      if (newCategoriesWhenMoved) {
        if (!newParentId || newParentId <= 0) {
          throw new Error(`Error in node_update(): provide a new parent_id (${newParentId}) when applying categories.`);
        }
        data['roles'] = { 'categories': newCategoriesWhenMoved };
      }


      let params = { 'body': JSON.stringify(data) };
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'PUT',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results') && jres['results'].hasOwnProperty('data')) {
          const item = jres['results']['data'];
          if(item['properties']) {
            retval = item['properties']['id'];
          }
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_update() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_update() finished: ${retval}`);
    }
    return retval;
  }

  /**
   * Update the names and descriptions of a Node.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} parentId The node which is updated.
   * @param {string} newName Optional: if set then the name of the node is renamed.
   * @param {string} newDescription Optional: if set then the description of the node is changed.
   * @param {object} newMultiNames Optional: if set then the names in different languages of the node are renamed. I.e. { 'en': 'name en', 'de': 'name de' }
   * @param {object} newMultiDescriptions Optional: if set then the descriptions in different languages of the node are changed. I.e. { 'en': 'desc en', 'de': 'desc de' }
   * @returns {number} the node id of the updated node
   */
  node_update_name = async(baseUrlCS, nodeId, newName, newDescription, newMultiNames, newMultiDescriptions) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_update_name() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, newName=${newName}, newDescription=${newDescription}, newMultiNames=${JSON.stringify(newMultiNames)}, newMultiDescriptions=${JSON.stringify(newMultiDescriptions)}`);
    }

    let retval = this.node_update(baseUrlCS, nodeId, 0, newName, newDescription, newMultiNames, newMultiDescriptions, null);

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_update_name() finished: ${retval}`);
    }
    return retval;
  }

  /**
   * Move a Node.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} parentId The node which is updated.
   * @param {number} newParentId Optional: if set then the node is moved to this new target.
   * @returns {number} the node id of the updated node
   */
  node_move = async(baseUrlCS, nodeId, newParentId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_move() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, newParentId=${newParentId}`)
    }

    let retval = this.node_update(baseUrlCS, nodeId, newParentId, null, null, null, null, null);

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_move() finished: ${retval}`)
    }
    return retval;
  }

  /**
   * Move a Node and apply a Category.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} parentId The node which is updated.
   * @param {number} newParentId Optional: if set then the node is moved to this new target.
   * @returns {number} the node id of the updated node
   */

  node_move_and_apply_category = async(baseUrlCS, nodeId, newParentId, newCategoriesWhenMoved) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_move_and_apply_category() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, newParentId=${newParentId}, newCategoriesWhenMoved=${JSON.stringify(newCategoriesWhenMoved)}`);
    }

    let retval = this.node_update(baseUrlCS, nodeId, newParentId, null, null, null, null, newCategoriesWhenMoved);

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_move_and_apply_category() finished: ${retval}`);
    }
    return retval;
  }

  /**
   * Delete a Node.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The node id to be deleted.
   * @returns {object} the result of the deleted node
   */
  node_delete = async(baseUrlCS, nodeId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_delete() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/nodes/${nodeId}`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'DELETE',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_delete() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_delete() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Download Node Content into a Local File.
   * 
   * @param {string} baseUrlCS  The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Node ID to get the information
   * @param {string} nodeVersion Optionally the version of the node
   * @param {string} localFoler The local path to store the file.
   * @param {string} localFileName The file name of the document.
   * @returns {object} result of download with structure {'message', 'location'}
   */
  node_download_file = async(baseUrlCS, nodeId, nodeVersion, localFoler, localFileName) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_download_file() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, nodeVersion=${nodeVersion}, localFoler=${localFoler}, localFileName=${localFileName}`);
    }

    let retval = { 'message': 'ok', 'location': ''};
    let apiendpoint = `api/v2/nodes/${nodeId}`;
    if (nodeVersion) {
      apiendpoint += `/versions/${nodeVersion}`;
    }
    apiendpoint += `/content`;

    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'GET',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doDownloadHttps(fs.createWriteStream(path.join(localFoler, localFileName)), options);
      } else {
        res = await this.doDownloadHttp(fs.createWriteStream(path.join(localFoler, localFileName)), options);
      }
      if (res['statusCode'] === 200) {
        // fs.writeFileSync(path.join(localFoler, localFileName), res['body']);
        //retval['file_size'] = res['body'].length;
        retval['location'] = path.join(localFoler, localFileName);
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_download_file() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_download_file() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Download Node Content as Byte Array.
   * 
   * @param {string} baseUrlCS  The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Node ID to get the information
   * @param {string} nodeVersion Optionally the version of the node
   * @returns {object} result of download with structure {'message', 'file_size', 'base64' }
   */
  node_download_bytes = async(baseUrlCS, nodeId, nodeVersion) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_download_bytes() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, nodeVersion=${nodeVersion}`);
    }

    let retval = { 'message': 'ok', 'file_size': 0, 'base64': ''};
    let apiendpoint = `api/v2/nodes/${nodeId}`;
    if (nodeVersion) {
      apiendpoint += `/versions/${nodeVersion}`;
    }
    apiendpoint += `/content`;

    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'GET',
          headers: req_headers
      };

      let chunks = [];

      const contentStream = new Writable({
        write(chunk, encoding, callback) {
          chunks.push(chunk);
          callback();
        }
      });

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doDownloadHttps(contentStream, options);
      } else {
        res = await this.doDownloadHttp(contentStream, options);
      }

      let buf = Buffer.concat(chunks);

      /*
      if (baseUrl['protocol'] === "https") {
        res = await this.doDownloadHttps(fs.createWriteStream(path.join(localFoler, localFileName)), options);
      } else {
        res = await this.doDownloadHttp(fs.createWriteStream(path.join(localFoler, localFileName)), options);
      }
      */

      if (res['statusCode'] === 200) {
        retval['file_size'] = buf.length;
        retval['base64'] = buf.toString('base64');
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_download_bytes() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_download_bytes() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Upload Document into Content Server from a Local File.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} parentId The parent id of container to which the document is uploaded.
   * @param {string} localFolder The local path to store the file.
   * @param {string} localFileName The local file name of the document.
   * @param {string} remoteFileName The remote file name of the document.
   * @param {object} categories Optional categories of the document. I.e. { "30724_2": "2023-03-20" }
   * @returns {number} the new node id of the uploaded document
   */
  node_upload_file = async(baseUrlCS, parentId, localFolder, localFileName, remoteFileName, categories) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_upload_file() start: baseUrlCS=${baseUrlCS}, parentId=${parentId}, localFolder=${localFolder}, localFileName=${localFileName}, remoteFileName=${remoteFileName}, categories=${JSON.stringify(categories)}`);
    }

    let retval = -1;
    let apiendpoint = `api/v2/nodes`;
    try {
      let filePath = path.join(localFolder, localFileName);
      let contentStream = fs.createReadStream(filePath);
      let contentLength = fs.statSync(filePath).size;

      let baseUrl = this._checkUrl(baseUrlCS);

      let data = {'type': 144, 'parent_id': parentId, 'name': remoteFileName};
      if (categories) {
        data['roles'] = { 'categories': categories };
      }

      let params = { 'body': JSON.stringify(data) };

      //let files = [{ 'param': 'file', 'filename': remoteFileName, 'mimetype': 'application/octet-stream', 'data': fs.readFileSync(path.join(localFolder, localFileName)) }];
      let files = [];

      let post_data = this._getFormData(params, files);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'multipart/form-data; boundary=' + post_data['boundary']
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'POST',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        // res = await this.doCallHttps(post_data['formdata'], options);
        res = await this.doUploadHttps(contentStream, contentLength, 'file', remoteFileName, 'application/octet-stream', post_data['boundary'], post_data['formdata'], options);
      } else {
        // res = await this.doCallHttp(post_data['formdata'], options);
        res = await this.doUploadHttp(contentStream, contentLength, 'file', remoteFileName, 'application/octet-stream', post_data['boundary'], post_data['formdata'], options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results') && jres['results'].hasOwnProperty('data')) {
          const item = jres['results']['data'];
          if(item['properties']) {
            retval = item['properties']['id'];
          }
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_upload_file() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_upload_file() finished: ${retval}`);
    }
    return retval;
  }

  /**
   * Upload Document into Content Server as Byte Array.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} parentId The parent id of container to which the document is uploaded.
   * @param {Buffer} contentBuffer The bytearray containing the file's content.
   * @param {string} remoteFileName The remote file name of the document.
   * @param {object} categories Optional categories of the document. I.e. { "30724_2": "2023-03-20" }
   * @returns {number} the new node id of the uploaded document
   */
  node_upload_bytes = async(baseUrlCS, parentId, contentBuffer, remoteFileName, categories) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_upload_bytes() start: baseUrlCS=${baseUrlCS}, parentId=${parentId}, contentBuffer=${contentBuffer}, remoteFileName=${remoteFileName}, categories=${JSON.stringify(categories)}`);
    }

    let retval = -1;
    let apiendpoint = `api/v2/nodes`;
    try {
      let contentStream = Readable.from(contentBuffer);
      let contentLength = contentBuffer.length;

      let baseUrl = this._checkUrl(baseUrlCS);

      let data = {'type': 144, 'parent_id': parentId, 'name': remoteFileName};
      if (categories) {
        data['roles'] = { 'categories': categories };
      }

      let params = { 'body': JSON.stringify(data) };

      //let files = [{ 'param': 'file', 'filename': remoteFileName, 'mimetype': 'application/octet-stream', 'data': contentBuffer }];
      let files = [];

      let post_data = this._getFormData(params, files);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'multipart/form-data; boundary=' + post_data['boundary'],
            'Content-Length': post_data['formdata'].length
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'POST',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        // res = await this.doCallHttps(post_data['formdata'], options);
        res = await this.doUploadHttps(contentStream, contentLength, 'file', remoteFileName, 'application/octet-stream', post_data['boundary'], post_data['formdata'], options);
      } else {
        // res = await this.doCallHttp(post_data['formdata'], options);
        res = await this.doUploadHttp(contentStream, contentLength, 'file', remoteFileName, 'application/octet-stream', post_data['boundary'], post_data['formdata'], options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results') && jres['results'].hasOwnProperty('data')) {
          const item = jres['results']['data'];
          if(item['properties']) {
            retval = item['properties']['id'];
          }
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_upload_bytes() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_upload_bytes() finished: ${retval}`);
    }
    return retval;
  }

  /**
   * Apply Category to a Node.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The node id to which the category is applied.
   * @param {object} category The category values. I.e. {"category_id":9830} (apply category and use default values) or {"category_id":9830,"9830_2":"new value"} (apply category and set a value) or {"category_id":9830,"9830_3_2_4":["","","new value"]} (apply category and set values in a set of a text field)
   * @returns {number} the node id of the changed node
   */
  node_category_add = async(baseUrlCS, nodeId, category) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_category_add() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, category=${JSON.stringify(category)}`);
    }

    let retval = -1;
    let apiendpoint = `api/v2/nodes/${nodeId}/categories`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = { 'body': JSON.stringify(category) };
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'POST',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres) {
          retval = nodeId;
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_category_add() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_category_add() finished: ${retval}`);
    }
    return retval;
  }

  /**
   * Update Category values of a Node.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The node id to which the category is applied.
   * @param {number} categoryId  The category id to which the values are applied.
   * @param {object} category The category values. I.e. {"category_id":9830} (apply category and use default values) or {"category_id":9830,"9830_2":"new value"} (apply category and set a value) or {"category_id":9830,"9830_3_2_4":["","","new value"]} (apply category and set values in a set of a text field)
   * @returns {number} the node id of the changed node
   */
  node_category_update = async(baseUrlCS, nodeId, categoryId, category) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_category_update() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, categoryId=${categoryId}, category=${JSON.stringify(category)}`);
    }

    let retval = -1;
    let apiendpoint = `api/v2/nodes/${nodeId}/categories/${categoryId}`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);
      let params = { 'body': JSON.stringify(category) };
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'PUT',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres) {
          retval = nodeId;
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_category_update() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_category_update() finished: ${retval}`);
    }
    return retval;
  }

  /**
   * Delete a Category from a Node.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The node id to which the category is applied.
   * @param {number} categoryId The category id which is removed from the node.
   * @returns {number} the node id of the changed node
   */
  node_category_delete = async(baseUrlCS, nodeId, categoryId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_category_delete() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, categoryId=${categoryId}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/nodes/${nodeId}/categories/${categoryId}`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'DELETE',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres) {
          retval = nodeId;
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_category_delete() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_category_delete() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Get Classifications of Node.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Node ID to get the information
   * @param {Array} filterFields The List to fetch only certain properties. I.e. ['data']
   * @returns {Array} list of classifications
   */
  node_classifications_get = async(baseUrlCS, nodeId, filterFields) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_classifications_get() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, filterFields=${filterFields}`);
    }

    let retval = [];
    let apiendpoint = `api/v1/nodes/${nodeId}/classifications`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = {};
      if (filterFields && filterFields.length > 0) {
        if (!params.hasOwnProperty('fields')) {
          params['fields'] = [];
        }
        for(let i=0; i<filterFields.length; i++) {
          params['fields'].push(filterFields[i]);
        }
      }

      let get_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint + ('?' + get_data) || '',
          method: 'GET',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString('utf8'));

        if (jres && jres.hasOwnProperty('data')) {
          let classList = jres['data'];
          if(classList && classList.length > 0) {
            for(let i=0; i<classList.length; i++) {
              let item = classList[i];
              if (item.hasOwnProperty('cell_metadata')) {
                delete item['cell_metadata'];
              }
              retval.push(item);
            }
          }
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_classifications_get() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_classifications_get() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Apply (Update/Delete) Classifications to Node.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Node ID to get the information
   * @param {boolean} applyToSubitems If set, apply the classifications to all sub-items.
   * @param {Array} classificationIds The List of classifications to be added to the node. I.e. [120571,120570]
   * @returns {number} the node id of the changed node
   */
  node_classifications_apply = async(baseUrlCS, nodeId, applyToSubitems, classificationIds) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_classifications_apply() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, applyToSubitems=${applyToSubitems}, classificationIds=${JSON.stringify(classificationIds)}`);
    }

    let retval = -1;
    let apiendpoint = `api/v1/nodes/${nodeId}/classifications`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let data = { 'apply_to_sub_items': applyToSubitems, 'class_id': classificationIds}
      let params = { 'body': JSON.stringify(data) };
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'POST',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        retval = nodeId;
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_classifications_apply() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_classifications_apply() finished: ${retval}`);
    }
    return retval;
  }

  /**
   * Get Details of serveral Nodes. Maximum of 250 Node IDs supported.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {Array} nodeIds The List of Nodes to get the details
   * @returns {object} node information with structure: { '<nodeid1>': {}, '<nodeid2>': {}}
   */
  nodes_get_details = async(baseUrlCS, nodeIds) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`nodes_get_details() start: baseUrlCS=${baseUrlCS}, nodeIds=${nodeIds}`);
    }

    let retval = { };
    let apiendpoint = `api/v2/nodes/list`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let data = { 'ids': nodeIds };
      let params = { 'body' : JSON.stringify(data) };

      let post_data = this._getFormData(params, []);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'multipart/form-data; boundary=' + post_data['boundary'],
            'Content-Length': post_data['formdata'].length
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'POST',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data['formdata'], options);
      } else {
        res = await this.doCallHttp(post_data['formdata'], options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          const nodes = jres['results'];

          for (let i=0; i<nodes.length; i++) {
            let node = nodes[i];
            if(node['data'] && node['data']['properties']) {

              let nodeId = node['data']['properties']['id'];
              if (nodeId && nodeId > 0) {
                retval[nodeId] = node['data'];
              }
            }
          }
        }

      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in nodes_get_details() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`nodes_get_details() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Get Sub Nodes - optionally include property filter, load category information, load permissions, load classifications.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Node ID to get the information
   * @param {Array} filterProperties The List to fetch only certain properties. I.e. ['id', 'name'] or ['id', 'name', 'type', 'type_name', 'name_multilingual', 'description_multilingual'] or [] for all properties
   * @param {boolean} loadCategories Optionally load categories of node.
   * @param {boolean} loadPermissions Optionally load permissions of node.
   * @param {boolean} loadClassifications Optionally load classifications of node.
   * @param {number} page The page number to fetch in the results
   * @returns {object} list of sub nodes with structure: { 'results': [{ 'properties': {}, 'categories': [], 'permissions': [], 'classifications': []}], 'page_total': 0 }
   */
  subnodes_get = async(baseUrlCS, nodeId, filterProperties, loadCategories, loadPermissions, loadClassifications, page) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`subnodes_get() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, filterProperties=${filterProperties}, loadCategories=${loadCategories}, loadPermissions=${loadPermissions}, loadClassifications=${loadClassifications}`);
    }

    let retval = { 'results': [], 'page_total': 0 };
    let apiendpoint = `api/v2/nodes/${nodeId}/nodes`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let limit = 200;
      let params = {};
      if (filterProperties && filterProperties.length > 0) {
        if (!params.hasOwnProperty('fields')) {
          params['fields'] = [];
        }
        let param = 'properties{' + filterProperties.join(',') + '}';
        params['fields'].push(param);
      }

      if (loadCategories) {
        if (!params.hasOwnProperty('fields')) {
          params['fields'] = [];
        }
        let param = 'categories';
        params['fields'].push(param);
        limit = 20;
      }

      if (loadPermissions) {
        if (!params.hasOwnProperty('fields')) {
          params['fields'] = [];
        }
        let param = 'permissions';
        params['fields'].push(param);

        if (!params.hasOwnProperty('expand')) {
          params['expand'] = [];
        }
        params['expand'].push('permissions{right_id}');
        limit = 20;
      }

      if (loadClassifications) {
        limit = 10;
      }

      params['limit'] = limit;
      if (page && page > 0) {
        params['page'] = page;
      }

      let get_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint + ('?' + get_data) || '',
          method: 'GET',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          const items = jres['results'];
          for (let i=0; i<items.length; i++) {
            let item = items[i];
            if(item['data'] && item['data']['properties']) {
              let line = {'properties': item["data"]["properties"], 'categories': [], 'permissions': { 'owner': {}, 'group': {}, 'public': {}, 'custom': [] }, 'classifications': []};

              if (loadCategories) {
                line['categories'] = item['data']['categories'];
              }

              if (loadPermissions && item['data']['permissions'] && item['data']['permissions'].length > 0) {
                for(let i=0; i<item['data']['permissions'].length; i++) {
                  const perms = item['data']['permissions'][i];
                  if (perms['type'] === 'owner') {
                    line['permissions']['owner'] = perms;
                  } else if(perms['type'] === 'group') {
                    line['permissions']['group'] = perms;
                  } else if(perms['type'] === 'public') {
                    line['permissions']['public'] = perms;
                  } else if(perms['type'] === 'custom') {
                    line['permissions']['custom'].push(perms);
                  } else {
                    throw new Error(`Error in subnodes_get() - permission type ${perms['type']} is not supported.`);
                  }
                }
              }

              if (loadClassifications) {
                try {
                  line['classifications'] = await this.node_classifications_get(baseUrlCS, item["data"]["properties"]["id"], ['data']);
                } catch(itemError) {
                  let error_message = `Error in subnodes_get() while getting classifications -> ${item["data"]["properties"]} -> ${itemError}`;
                  console.error(error_message);
                }
              }

              retval['results'].push(line);

            }
          }
        }

        if (jres['collection'] && jres['collection']['paging'] && jres['collection']['paging']['page_total']) {
            retval['page_total'] = jres['collection']['paging']['page_total'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in subnodes_get() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`subnodes_get() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  // subnodes_filter
  /**
   * Filter for specific Sub Nodes. Max 200 entries are returned.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Parent Node ID to load the Sub Nodes
   * @param {string} filterName Filter result on the provided name: I.e. "OTHCM_WS_Employee_Categories"
   * @param {boolean} filterContainerOnly Apply filter only on Containers (i.e. Folders).
   * @param {boolean} exactMatch The name is matched fully -> filter out partial matches.
   * @returns {Array} list of sub nodes with structure: [{ 'properties': {'id', 'name'}}]
   */
  subnodes_filter = async(baseUrlCS, nodeId, filterName, filterContainerOnly, exactMatch) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`subnodes_filter() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, filterName=${filterName}, filterContainerOnly=${filterContainerOnly}, exactMatch=${exactMatch}`);
    }

    let retval = [];
    let apiendpoint = `api/v2/nodes/${nodeId}/nodes`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = { 'limit': 200, 'fields': ['properties{id,name}'], 'where_name': filterName };
      if (filterContainerOnly) {
        params['where_type'] = -1;
      }

      let get_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint + ('?' + get_data) || '',
          method: 'GET',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          const items = jres['results'];
          for (let i=0; i<items.length; i++) {
            let item = items[i];
            if(item['data'] && item['data']['properties']) {
              if (exactMatch && item["data"]["properties"]['name'] === filterName) {
                let line = {'properties': item["data"]["properties"]};
                retval.push(line);
              } else if (!exactMatch) {
                let line = {'properties': item["data"]["properties"]};
                retval.push(line);
              }
            }
          }
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in subnodes_filter() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`subnodes_filter() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Get Category Definition of a Category.
   * 
   * @param {string} baseUrlCS 
   * @param {number} nodeId 
   * @returns {object} category definition of category with structure: { 'properties': {'id', 'name', 'type', 'type_name'}, 'forms': []}
   */
  category_definition_get = async(baseUrlCS, nodeId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`category_definition_get() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}`);
    }

    let retval = { 'properties': {}, 'forms': []};
    let apiendpoint = `api/v2/nodes/${nodeId}`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let filterProperties = ['id', 'name', 'type', 'type_name'];

      let params = { };

      if (filterProperties && filterProperties.length > 0) {
        if (!params.hasOwnProperty('fields')) {
          params['fields'] = [];
        }
        let param = 'properties{' + filterProperties.join(',') + '}';
        params['fields'].push(param);
      }


      let get_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint + ('?' + get_data) || '',
          method: 'GET',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          const item = jres['results'];
          if(item['data'] && item['data']['properties']) {
            retval['properties'] = item['data']['properties'];
            if (item["data"]["properties"]['type'] && item["data"]["properties"]['type'] === 131) {
              retval['forms'] = await this.specific_get(baseUrlCS, nodeId);
            } else {
              throw new Error(`node_id ${nodeId} was expected to be a Category, but it is a ${item["data"]["properties"]['type_name']}`);
            }
          }
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in category_definition_get() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`category_definition_get() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Get Specific information of Node. I.e. category definition of a category node
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Node ID to get the information
   * @returns {Array} specific information of node
   */
  specific_get = async(baseUrlCS, nodeId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`specific_get() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}`);
    }

    let retval = [];
    let apiendpoint = `api/v1/forms/nodes/properties/specific`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = { 'id': nodeId };

      let get_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint + ('?' + get_data) || '',
          method: 'GET',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('forms')) {
          const items = jres['forms'];
          for (let i=0; i<items.length; i++) {
            const item = items[i];
            let line = {'fields': {}, 'data': {}};
            if (item['schema']) {
              line['fields'] = item["schema"];
            }
            if (item['data']) {
              line['data'] = item["data"];
            }
            retval.push(line);
          }
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in specific_get() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`specific_get() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Get Category mappings of the attributes with id and name as a dict object
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Node ID to get the information
   * @returns {object} dictionaries to map the ids and names of a category attributes with the structure: { 'main_name': '', 'main_id': 0, 'map_names': {}, 'map_ids': {}}
   */
  category_get_mappings = async(baseUrlCS, nodeId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`category_get_mappings() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}`);
    }

    let retval = { 'main_name': '', 'main_id': 0, 'map_names': {}, 'map_ids': {}};

    let res = await this.category_definition_get(baseUrlCS, nodeId);

    let categoryName = res['properties']['name'];
    let categoryId = res['properties']['id'];

    retval['main_name'] = categoryName;
    retval['main_id'] = categoryId;

    if (res['forms'] && res['forms'].length > 0) {
      for(let i=0; i<res['forms'].length; i++) {
        let f = res['forms'][i];
        if (f && f['fields'] && f['fields']['properties']) {
          let props = f['fields']['properties'];

          for (let prop in props) {
            if (props[prop]['title']) {
              let fieldId = `${prop}`;
              let fieldName = props[prop]['title'];
              retval['map_names'][fieldName] = fieldId;
              retval['map_ids'][fieldId] = fieldName;

              if (props[prop]['items'] && props[prop]['items']['properties']) {
                let subprops = props[prop]['items']['properties'];

                for (let subprop in subprops) {
                  if (subprops[subprop]['title']) {
                    let subFieldId = `${subprop}`;
                    let subFieldName = subprops[subprop]['title'];
                    retval['map_names'][`${fieldName}:${subFieldName}`] = subFieldId;
                    retval['map_ids'][subFieldId] = `${fieldName}:${subFieldName}`;
                  }
                }
              }
            }
          }
        }
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`category_get_mappings() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  // volumes_get
  /**
   * Get Volumes of Content Server
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @returns {Array} all available volumes of Content Server
   */
  volumes_get = async(baseUrlCS) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`volumes_get() start: baseUrlCS=${baseUrlCS}`);
    }

    let retval = [];
    let apiendpoint = `api/v2/volumes`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = {'fields': ['properties{id,name}']};

      let get_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint + ('?' + get_data) || '',
          method: 'GET',
          headers: req_headers
      };

      let res = [];
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          const items = jres['results'];
          for (let i=0; i<items.length; i++) {
            const item = items[i];
            if (item['data'] && item["data"]["properties"]) {
              let line = {'properties': item["data"]["properties"]};
              retval.push(line);
            }
          }
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in volumes_get() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`volumes_get() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Get ID and Name of a Node by Path Information
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {string} csPath The path of the node. I.e. Content Server Categories:SuccessFactors:OTHCM_WS_Employee_Categories:Personal Information
   * @returns {object} ID and Name of the last node of the given path
   */
  path_to_id = async(baseUrlCS, csPath) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`path_to_id() start: baseUrlCS=${baseUrlCS}, csPath=${csPath}`);
    }

    let retval = { };

    if (csPath) {
      let volName = '';
      let volId = 0;
      let pathLst = csPath.split(':');
      if (pathLst.length > 0){
        volName = pathLst[0];
      }

      if (volName) {
        if (!this._volumesHash || !this._volumesHash.hasOwnProperty(baseUrlCS)) {
          let res = await this.volumes_get(baseUrlCS);
          this._volumesHash[baseUrlCS] = {};

          for (let i=0; i<res.length; i++) {
            let item = res[i];
            if (item['properties']) {
              let line = item['properties'];
              this._volumesHash[baseUrlCS][line["name"]] = line["id"];
              this._volumesHash[baseUrlCS][line["id"]] = line["name"];
            }
          }
        }

        if (this._volumesHash.hasOwnProperty(baseUrlCS) && this._volumesHash[baseUrlCS].hasOwnProperty(volName)) {
          volId = this._volumesHash[baseUrlCS][volName];
        }
      }

      if (volId > 0) {
        if (pathLst.length > 1) {
          let cnt = 1;
          let parentNode = volId;
          for(let i=1; i<pathLst.length; i++) {
            let pathItem = pathLst[i];
            cnt ++;

            if (cnt < pathLst.length) {
              // container
              let itemRes = await this.subnodes_filter(baseUrlCS, parentNode, pathItem, true, true);
              if (itemRes && itemRes.length > 0 && itemRes[0]['properties']) {
                parentNode = itemRes[0]['properties']['id'];
              } else {
                throw new Error(`Error in path_to_id() -> ${pathItem} not found in path.`);
              }
            } else {
              // last item -> might be no container
              let itemRes = await this.subnodes_filter(baseUrlCS, parentNode, pathItem, false, true);
              if (itemRes && itemRes.length > 0 && itemRes[0]['properties']) {
                parentNode = itemRes[0]['properties']['id'];
                retval = {'id': itemRes[0]['properties']['id'], 'name': itemRes[0]['properties']['name']};
              } else {
                throw new Error(`Error in path_to_id() -> last item ${pathItem} not found in path.`);
              }
            }
          }
        }
      } else {
        throw new Error(`Error in path_to_id() -> ${volName} not found in volumes.`);
      }

    } else {
      throw new Error(`Error in path_to_id() -> please provide a valid path with the format: i.e. "Content Server Categories:SuccessFactors:OTHCM_WS_Employee_Categories:Personal Information"`);
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`path_to_id() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Get Information on a Group Member
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} groupId The Group ID.
   * @returns {object} Details of the Member Group
   */
  member_get = async(baseUrlCS, groupId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`member_get() start: baseUrlCS=${baseUrlCS}, groupId=${groupId}`);
    }

    let retval = {};
    let apiendpoint = `api/v1/members/${groupId}`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = { 'expand': 'member' };

      let get_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint + ('?' + get_data) || '',
          method: 'GET',
          headers: req_headers
      };

      let res = [];
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('data')) {
          retval = jres['data'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in member_get() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`member_get() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  // search
  /**
   * Search in Content Server
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {string} searchTerm The search term: I.e. Personal Information
   * @param {number} subType The sub_type of the node to be searched for: 0=folder, 144=document, 131=category, ...
   * @param {number} locationNode The location (node_id) to be search in
   * @param {number} page The page number to fetch in the results
   * @returns {object} found nodes that correspond to the search criteria with structure: { 'results': [{'id', 'name', 'parent_id'}], 'page_total': 0 }
   */
  search = async(baseUrlCS, searchTerm, subType, locationNode, page) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`search() start: baseUrlCS=${baseUrlCS}, searchTerm=${searchTerm}, subType=${subType}, locationNode=${locationNode}, page=${page}`);
    }

    let retval = { 'results': [], 'page_total': 0 };
    let apiendpoint = `api/v2/search`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let data = {'limit': 100, 'where': ''};
      data['where'] = `OTName: "${searchTerm.replaceAll('"', '\\"')}" and OTSubType: ${subType} and OTLocation: ${locationNode}`;
      let params = { 'body': JSON.stringify(data)};
      
      if (page && page > 0) {
        params['page'] = page;
      }

      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'POST',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          const items = jres['results'];
          for (let i=0; i<items.length; i++) {
            let item = items[i];
            if(item['data'] && item['data']['properties']) {
              let line = {'id': item["data"]["properties"]["id"], 'name': item["data"]["properties"]["name"], 'parent_id': item["data"]["properties"]["parent_id"]};
              retval['results'].push(line);
            }
          }

          if (jres['collection'] && jres['collection']['paging'] && jres['collection']['paging']['page_total']) {
              retval['page_total'] = jres['collection']['paging']['page_total'];
          }
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in search() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`search() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Get ID and Name of a Node by Path Information
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {string} categoryPath The path of the category. I.e. Content Server Categories:SuccessFactors:OTHCM_WS_Employee_Categories:Personal Information
   * @param {string} attributeName The attribute name inside the category. I.e. 'User ID' or 'Personnel Number'
   * @returns {object} ID, Name of the category and Attribute Key of the attribute_name. I.e. {'category_id': 30643, 'category_name': 'Personal Information', 'attribute_key': '30643_26', 'attribute_name': 'User ID'}
   */
  category_attribute_id_get = async(baseUrlCS, categoryPath, attributeName) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`category_attribute_id_get() start: baseUrlCS=${baseUrlCS}, categoryPath=${categoryPath}, attributeName=${attributeName}`);
    }

    let retval = { };

    if (!this._categoryHash || !this._categoryHash.hasOwnProperty(baseUrlCS)) {
      this._categoryHash[baseUrlCS] = { 'category_path_to_id': {} };
    }

    if (!this._categoryHash[baseUrlCS]['category_path_to_id'].hasOwnProperty(categoryPath)) {
      let res = await this.path_to_id(baseUrlCS, categoryPath);

      if (res && res.hasOwnProperty('id')) {
        let catId = res['id'];
        this._categoryHash[baseUrlCS]['category_path_to_id'][categoryPath] = { 'category_id': catId, 'category_name': res['name'], 'attribute_map': {}};
        res = await this.category_get_mappings(baseUrlCS, catId);

        if (res && res.hasOwnProperty('map_names')) {
          this._categoryHash[baseUrlCS]['category_path_to_id'][categoryPath]['attribute_map'] = res['map_names'];
        } else {
          throw new Error(`Error in category_attribute_id_get() -> ${categoryPath} not found. ID = ${catId}.`);
        }
      } else {
        throw new Error(`Error in category_attribute_id_get() -> ${categoryPath} not found. Call to path_to_id() returned an empty result.`);
      }
    }

    let catId = this._categoryHash[baseUrlCS]['category_path_to_id'][categoryPath]['category_id'];
    retval['category_id'] = catId;
    retval['category_name'] = this._categoryHash[baseUrlCS]['category_path_to_id'][categoryPath]['category_name'];

    if (this._categoryHash[baseUrlCS]['category_path_to_id'][categoryPath]['attribute_map'].hasOwnProperty(attributeName)) {
      retval['attribute_key'] = this._categoryHash[baseUrlCS]['category_path_to_id'][categoryPath]['attribute_map'][attributeName];
      retval['attribute_name'] = attributeName;
    } else {
      throw new Error(`Error in category_attribute_id_get() -> attribute "${attributeName}" not found in (${catId}) ${categoryPath}.`);
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`category_attribute_id_get() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Get all Smart Document Types of Content Server
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @returns {Array} all available Smart Document Types of Content Server
   */
  smartdoctypes_get_all = async(baseUrlCS) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctypes_get_all() start: baseUrlCS=${baseUrlCS}`);
    }

    let retval = [];
    let apiendpoint = `api/v2/smartdocumenttypes`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = { };

      let get_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint + ('?' + get_data) || '',
          method: 'GET',
          headers: req_headers
      };

      let res = [];
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results') && jres['results'].hasOwnProperty('data')) {
          retval = jres['results']['data'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctypes_get_all() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctypes_get_all() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Get Rules of a specific Smart Document Type
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} smartdoctypeId The Smart Document Type ID to get the details.
   * @returns {Array} Rules for the Smart Document Type
   */
  smartdoctypes_rules_get = async(baseUrlCS, smartdoctypeId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctypes_rules_get() start: baseUrlCS=${baseUrlCS}, smartdoctypeId=${smartdoctypeId}`);
    }

    let retval = [];
    let apiendpoint = `api/v2/smartdocumenttypes/smartdocumenttypedetails`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = { 'smart_document_type_id': smartdoctypeId };

      let get_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint + ('?' + get_data) || '',
          method: 'GET',
          headers: req_headers
      };

      let res = [];
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results') && jres['results'].hasOwnProperty('data')) {
          retval = jres['results']['data'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctypes_rules_get() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctypes_rules_get() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Get the details of a specific Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to get the details.
   * @returns {Array} Get Details of the Smart Document Type Rule
   */
  smartdoctype_rule_detail_get = async(baseUrlCS, ruleId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_detail_get() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}`);
    }

    let retval = [];
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = { };

      let get_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint + ('?' + get_data) || '',
          method: 'GET',
          headers: req_headers
      };

      let res = [];
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results') && jres['results'].hasOwnProperty('forms')) {
          retval = jres['results']['forms'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_detail_get() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_detail_get() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Add a new Smart Document Type
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} parentId The Parent ID of the container in which the Smart Document Type is created.
   * @param {number} classificationId The Classification ID the Smart Document Type is referred.
   * @param {string} smartdoctypeName The Name of the Smart Document Type.
   * @returns {number} the ID of the Smart Document Type
   */
  smartdoctype_add = async(baseUrlCS, parentId, classificationId, smartdoctypeName) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_add() start: baseUrlCS=${baseUrlCS}, parentId=${parentId}, classificationId=${classificationId}, smartdoctypeName=${smartdoctypeName}`);
    }

    let retval = -1;
    let apiendpoint = `api/v1/nodes`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let data = {'type': 877, 'type_name': 'Add Smart Document Type', 'container': true, 'parent_id': parentId, 'inactive': true, 'classificationId': classificationId, 'anchorTitle': '', 'anchorTitleShort': smartdoctypeName, 'name': smartdoctypeName, 'classification': classificationId};
      let params = {'body': JSON.stringify(data)};

      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'POST',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('id')) {
          retval = jres['id'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_add() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_add() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Add Workspace Template to a new Smart Document Type
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} smartdoctypeId The Node ID of the Smart Document Type.
   * @param {number} classificationId The Classification ID the Smart Document Type is referred.
   * @param {number} workspacetemplateId The Workspace Template ID.
   * @returns {object} the result of the action. I.e. {'is_othcm_template': True, 'ok': True, 'rule_id': 11, 'statusCode': 200}
   */
  smartdoctype_workspacetemplate_add = async(baseUrlCS, smartdoctypeId, classificationId, workspacetemplateId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_workspacetemplate_add() start: baseUrlCS=${baseUrlCS}, smartdoctypeId=${smartdoctypeId}, classificationId=${classificationId}, workspacetemplateId=${workspacetemplateId}`);
    }

    let retval = { };
    let apiendpoint = `api/v2/smartdocumenttypes/rules`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = { 'smart_document_type_id': smartdoctypeId, 'classification_id': classificationId, 'template_id': workspacetemplateId};

      let post_data = this._getFormData(params, []);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'multipart/form-data; boundary=' + post_data['boundary'],
            'Content-Length': post_data['formdata'].length
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'POST',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data['formdata'], options);
      } else {
        res = await this.doCallHttp(post_data['formdata'], options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_workspacetemplate_add() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_workspacetemplate_add() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Add/update the Set Context tab for a Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @param {number} basedOnCategoryId The Category ID for the document metadata. I.e. default category can be found under: Content Server Categories:Document Types:Document Type Details
   * @param {number} locationId The Target Location ID in the workspace template.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200, 'updatedAttributeIds': [2], 'updatedAttributeNames': ['Date of Origin']}
   */
  smartdoctype_rule_context_save = async(baseUrlCS, ruleId, basedOnCategoryId, locationId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_context_save() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}, basedOnCategoryId=${basedOnCategoryId}, locationId=${locationId}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/context`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let data = {'location': locationId, 'based_on_category': `${basedOnCategoryId}`, 'rule_expression': {'expressionText': '', 'expressionData': [], 'expressionDataKey': ''}, 'mimetype': [''], 'bot_action': 'update'};

      let params = { 'body': JSON.stringify(data) };
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'PUT',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_context_save() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_context_save() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Add/update the Make Mandatory tab for a Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @param {boolean} isMandatory The mandatory flag to be set.
   * @param {string} botAction The action: use 'add' to create the tab or 'update' to update the values.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200}
   */
  smartdoctype_rule_mandatory_save = async(baseUrlCS, ruleId, isMandatory, botAction) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_mandatory_save() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}, isMandatory=${isMandatory}, botAction=${botAction}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/makemandatory`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let data = {'mandatory': isMandatory, 'bot_action': botAction};

      let params = { 'body': JSON.stringify(data) };
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'PUT',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_mandatory_save() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_mandatory_save() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Delete the Make Mandatory tab from a Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200}
   */
  smartdoctype_rule_mandatory_delete = async(baseUrlCS, ruleId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_mandatory_delete() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/makemandatory`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'DELETE',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_mandatory_delete() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_mandatory_delete() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Add/update the Check Document Expiration tab for a Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @param {boolean} validityRequired Is Validity Check Reqired.
   * @param {number} basedOnAttribute Attribute Number for i.e. Date Of Origin to calculate the expiration date. I.e. 2 if default "Category Document Type" Details is used.
   * @param {number} numYears Number of years validity.
   * @param {number} numMonths Number of months validity.
   * @param {string} botAction The action: use 'add' to create the tab or 'update' to update the values.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200, 'updatedAttributeIds': [2], 'updatedAttributeNames': ['Date of Origin']}
   */
  smartdoctype_rule_documentexpiration_save = async(baseUrlCS, ruleId, validityRequired, basedOnAttribute, numYears, numMonths, botAction) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_documentexpiration_save() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}, validityRequired=${validityRequired}, basedOnAttribute=${basedOnAttribute}, numYears=${numYears}, numMonths=${numMonths}, botAction=${botAction}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/completenesscheck`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let data = {'validity_required': validityRequired, 'based_on_attribute': `${basedOnAttribute}`, 'validity_years': numYears, 'validity_months': `${numMonths}`, 'bot_action': botAction};

      let params = { 'body': JSON.stringify(data) };
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'PUT',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_documentexpiration_save() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_documentexpiration_save() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Delete the Check Document Expiration tab from a Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200}
   */
  smartdoctype_rule_documentexpiration_delete = async(baseUrlCS, ruleId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_documentexpiration_delete() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/completenesscheck`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'DELETE',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_mandatory_delete() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_documentexpiration_delete() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Add/update the Generate Document tab for a Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @param {boolean} isDocGen The document generation flag to be set.
   * @param {boolean} onlyGenDocsAllowed Allow only Generated Documents for Upload.
   * @param {string} botAction The action: use 'add' to create the tab or 'update' to update the values.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200}
   */
  smartdoctype_rule_generatedocument_save = async(baseUrlCS, ruleId, isDocGen, onlyGenDocsAllowed, botAction) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_generatedocument_save() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}, isDocGen=${isDocGen}, onlyGenDocsAllowed=${onlyGenDocsAllowed}, botAction=${botAction}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/createdocument`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let data = {'docgen': isDocGen, 'docgen_upload_only': onlyGenDocsAllowed, 'bot_action': botAction};

      let params = { 'body': JSON.stringify(data) };
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'PUT',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_generatedocument_save() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_generatedocument_save() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Delete the Generate Document tab from a Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200}
   */
  smartdoctype_rule_generatedocument_delete = async(baseUrlCS, ruleId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_generatedocument_delete() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/createdocument`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'DELETE',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_generatedocument_delete() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_generatedocument_delete() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Add/update the Allow Upload tab for a Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @param {Array} members The list of groups to be set.
   * @param {string} botAction The action: use 'add' to create the tab or 'update' to update the values.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200}
   */
  smartdoctype_rule_allowupload_save = async(baseUrlCS, ruleId, members, botAction) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_allowupload_save() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}, members=${members}, botAction=${botAction}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/uploadcontrol`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let membersData = [];

      for (let i=0; i<members.length; i++) {
        let grp = members[i];
        let grpDetails = await this.member_get(baseUrlCS, grp);
        let memb = Object.assign({}, grpDetails);  // copy object
        memb['data'] = {};
        memb['data']['properties'] = Object.assign({}, grpDetails); // copy object
        membersData.push(memb)
      }

      let data = {'member': members, 'bot_action': botAction, 'membersData': membersData};

      let params = { 'body': JSON.stringify(data) };
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'PUT',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_allowupload_save() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_allowupload_save() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Delete the Allow Upload tab from a Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200}
   */
  smartdoctype_rule_allowupload_delete = async(baseUrlCS, ruleId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_allowupload_delete() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/uploadcontrol`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'DELETE',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_allowupload_delete() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_allowupload_delete() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Add/update the Upload with Approval tab for a Smart Document Type Rule. An additional Workflow Map is required with the Map > General > Role Implementation being set to Map Based.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @param {boolean} reviewRequired The Review Required flag to be set.
   * @param {number} workflowId The Workflow ID of the Approval Flow.
   * @param {Array} wfRoles The list of workflow roles to be set. I.e. [{'wfrole': 'Approver', 'member': 2001 }]
   * @param {string} botAction The action: use 'add' to create the tab or 'update' to update the values.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200}
   */
  smartdoctype_rule_uploadapproval_save = async(baseUrlCS, ruleId, reviewRequired, workflowId, wfRoles, botAction) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_uploadapproval_save() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}, reviewRequired=${reviewRequired}, workflowId=${workflowId}, wfRoles=${wfRoles}, botAction=${botAction}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/uploadwithapproval`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let roleHash = {};
      for (let i=0; i<wfRoles.length; i++) {
        let role = wfRoles[i];
        if (!roleHash.hasOwnProperty(role['wfrole'])) {
            roleHash[role['wfrole']] = [];
        }
        roleHash[role['wfrole']].push(role['member']);
      }

      let roleMappings = [];
      for (let roleKey in roleHash) {
          let roleMap = { 'workflowRole': roleKey, 'member': 0, 'membersData': [] }

          for (let i=0; i<roleHash[roleKey].length; i++) {
            let groupId = roleHash[roleKey][i];
            roleMap['member'] = groupId;
            let grpDetails = await this.member_get(baseUrlCS, groupId);
            let memb = Object.assign({}, grpDetails);
            memb['data'] = {};
            memb['data']['properties'] = Object.assign({}, grpDetails);
            roleMap['membersData'].push(memb);
          }

          roleMappings.push(roleMap);
      }

      let data = {'review_required': reviewRequired, 'review_workflow_location': workflowId, 'role_mappings': roleMappings, 'bot_action': botAction}

      let params = { 'body': JSON.stringify(data) };
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'PUT',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_uploadapproval_save() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_uploadapproval_save() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Delete the Upload with Approval tab from a Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200}
   */
  smartdoctype_rule_uploadapproval_delete = async(baseUrlCS, ruleId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_uploadapproval_delete() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/uploadwithapproval`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'DELETE',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_uploadapproval_delete() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_uploadapproval_delete() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Add/update the Riminder tab for a Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @param {boolean} isReminder The reminder flag to be set.
   * @param {string} botAction The action: use 'add' to create the tab or 'update' to update the values.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200}
   */
  smartdoctype_rule_reminder_save = async(baseUrlCS, ruleId, isReminder, botAction) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_reminder_save() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}, isReminder=${isReminder}, botAction=${botAction}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/reminder`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let data = {'rstype': isReminder, 'bot_action': botAction};

      let params = { 'body': JSON.stringify(data) };
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'PUT',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        let bodyStr = res['body'].toString("utf8");
        if (bodyStr) {
          const jres = JSON.parse(bodyStr);

          if (jres && jres.hasOwnProperty('results')) {
            retval = jres['results'];
          }
        } else {
          throw new Error(`Missing Permissions to execute this action - check volume Reminders:Successfactors Client - Failed to add Bot "reminder" on template.`);
        }

      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_reminder_save() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_reminder_save() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Delete the Reminder tab from a Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200}
   */
  smartdoctype_rule_reminder_delete = async(baseUrlCS, ruleId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_reminder_delete() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/reminder`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'DELETE',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_reminder_delete() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_reminder_delete() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Add/update the Review Upload tab for a Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @param {boolean} reviewRequired The review required flag to be set.
   * @param {string} reviewText Set the review text.
   * @param {Array} members The list of groups to be set.
   * @param {string} botAction The action: use 'add' to create the tab or 'update' to update the values.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200}
   */
  smartdoctype_rule_reviewuploads_save = async(baseUrlCS, ruleId, reviewRequired, reviewText, members, botAction) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_reviewuploads_save() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}, reviewRequired=${reviewRequired}, reviewText=${reviewText}, members=${members}, botAction=${botAction}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/reviewoption`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let membersData = [];

      for (let i=0; i<members.length; i++) {
        let grp = members[i];
        let grpDetails = await this.member_get(baseUrlCS, grp);
        let memb = Object.assign({}, grpDetails);  // copy object
        memb['data'] = {};
        memb['data']['properties'] = Object.assign({}, grpDetails); // copy object
        membersData.push(memb)
      }

      let data = {'review_required': reviewRequired, 'reviewtext': reviewText, 'member': members, 'bot_action': botAction, 'membersData': membersData};

      let params = { 'body': JSON.stringify(data) };
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'PUT',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_reviewuploads_save() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_reviewuploads_save() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Delete the Review Upload tab from a Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200}
   */
  smartdoctype_rule_reviewuploads_delete = async(baseUrlCS, ruleId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_reviewuploads_delete() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/reviewoption`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'DELETE',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_reviewuploads_delete() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_reviewuploads_delete() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Add/update the Allow Delete tab for a Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @param {Array} members The list of groups to be set.
   * @param {string} botAction The action: use 'add' to create the tab or 'update' to update the values.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200}
   */
  smartdoctype_rule_allowdelete_save = async(baseUrlCS, ruleId, members, botAction) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_allowdelete_save() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}, members=${members}, botAction=${botAction}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/deletecontrol`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let membersData = [];

      for (let i=0; i<members.length; i++) {
        let grp = members[i];
        let grpDetails = await this.member_get(baseUrlCS, grp);
        let memb = Object.assign({}, grpDetails);  // copy object
        memb['data'] = {};
        memb['data']['properties'] = Object.assign({}, grpDetails); // copy object
        membersData.push(memb)
      }

      let data = {'member': members, 'bot_action': botAction, 'membersData': membersData};

      let params = { 'body': JSON.stringify(data) };
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'PUT',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_allowdelete_save() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_allowdelete_save() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Delete the Allow Delete tab from a Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200}
   */
  smartdoctype_rule_allowdelete_delete = async(baseUrlCS, ruleId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_allowdelete_delete() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/deletecontrol`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'DELETE',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_allowdelete_delete() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_allowdelete_delete() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Add/update the Delete with Approval tab for a Smart Document Type Rule. An additional Workflow Map is required with the Map > General > Role Implementation being set to Map Based.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @param {boolean} reviewRequired The Review Required flag to be set.
   * @param {number} workflowId The Workflow ID of the Approval Flow.
   * @param {Array} wfRoles The list of workflow roles to be set. I.e. [{'wfrole': 'Approver', 'member': 2001 }]
   * @param {string} botAction The action: use 'add' to create the tab or 'update' to update the values.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200}
   */
  smartdoctype_rule_deletewithapproval_save = async(baseUrlCS, ruleId, reviewRequired, workflowId, wfRoles, botAction) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_deletewithapproval_save() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}, reviewRequired=${reviewRequired}, workflowId=${workflowId}, wfRoles=${wfRoles}, botAction=${botAction}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/deletewithapproval`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let roleHash = {};
      for (let i=0; i<wfRoles.length; i++) {
        let role = wfRoles[i];
        if (!roleHash.hasOwnProperty(role['wfrole'])) {
            roleHash[role['wfrole']] = [];
        }
        roleHash[role['wfrole']].push(role['member']);
      }

      let roleMappings = [];
      for (let roleKey in roleHash) {
          let roleMap = { 'workflowRole': roleKey, 'member': 0, 'membersData': [] }

          for (let i=0; i<roleHash[roleKey].length; i++) {
            let groupId = roleHash[roleKey][i];
            roleMap['member'] = groupId;
            let grpDetails = await this.member_get(baseUrlCS, groupId);
            let memb = Object.assign({}, grpDetails);
            memb['data'] = {};
            memb['data']['properties'] = Object.assign({}, grpDetails);
            roleMap['membersData'].push(memb);
          }

          roleMappings.push(roleMap);
      }

      let data = {'review_required': reviewRequired, 'review_workflow_location': workflowId, 'role_mappings': roleMappings, 'bot_action': botAction}

      let params = { 'body': JSON.stringify(data) };
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'PUT',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_deletewithapproval_save() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_deletewithapproval_save() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Delete the Delete with Approval tab from a Smart Document Type Rule
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} ruleId The Rule ID to update.
   * @returns {object} the result of the action. I.e. {'ok': True, 'statusCode': 200}
   */
  smartdoctype_rule_deletewithapproval_delete = async(baseUrlCS, ruleId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_deletewithapproval_delete() start: baseUrlCS=${baseUrlCS}, ruleId=${ruleId}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/smartdocumenttypes/rules/${ruleId}/bots/deletewithapproval`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'DELETE',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in smartdoctype_rule_deletewithapproval_delete() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`smartdoctype_rule_deletewithapproval_delete() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Search for a Business Workspace by Business Object Type and ID
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {string} logicalSystem The Logical System customized under the Connections to Business Applications (External Systems). I.e. SuccessFactors
   * @param {string} boType The Business Object Type. I.e. sfsf:user or BUS1065
   * @param {string} boId The Business Object ID. I.e. 2100000
   * @param {number} page The page number to fetch in the results
   * @returns {object} found businessworkspaces that correspond to the search criteria with structure: { 'results': [{'id', 'name', 'parent_id'}], 'page_total': 0 }
   */
  businessworkspace_search = async(baseUrlCS, logicalSystem, boType, boId, page) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`businessworkspace_search() start: baseUrlCS=${baseUrlCS}, logicalSystem=${logicalSystem}, boType=${boType}, boId=${boId}, page=${page}`);
    }

    let retval = { 'results': [], 'page_total': 0 };
    let apiendpoint = `api/v2/businessworkspaces`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = { 'where_ext_system_id': logicalSystem, 'where_bo_type': boType, 'where_bo_id': boId, 'expanded_view': 0, 'page': page, 'limit': 200 };

      let get_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint + ('?' + get_data) || '',
          method: 'GET',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString('utf8'));

        if (jres && jres.hasOwnProperty('results')) {
          const items = jres['results'];
          for (let i=0; i<items.length; i++) {
            let item = items[i];
            if(item['data'] && item['data']['properties']) {
              let line = {'id': item["data"]["properties"]["id"], 'name': item["data"]["properties"]["name"], 'parent_id': item["data"]["properties"]["parent_id"]};
              retval['results'].push(line);
            }
          }

          if (jres.hasOwnProperty('paging')) {
              retval['page_total'] = jres['paging']['page_total'];
          }
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in businessworkspace_search() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`businessworkspace_search() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Get available Smart Document Types of Business Workspace
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} bwsId The Node ID of the Business Workspace
   * @returns {Array} available Smart Document Types of the requested Business Workspace: available Smart Document Types of the requested Business Workspace: [{ 'classification_id': 0, 'classification_name': '', 'classification_description': '', 'category_id': 0, 'location': '', 'document_generation': false, 'required': false, 'template_id': 0 }]
   */
  businessworkspace_smartdoctypes_get = async(baseUrlCS, bwsId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`businessworkspace_smartdoctypes_get() start: baseUrlCS=${baseUrlCS}, bwsId=${bwsId}`);
    }

    let retval = [];
    let apiendpoint = `api/v2/businessworkspaces/${bwsId}/doctypes`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = { 'skip_validation': false, 'document_type_rule': true, 'document_generation_only': false, 'sort_by': 'DocumentType', 'parent_id': bwsId, 'filter_by_location': true };

      let get_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint + ('?' + get_data) || '',
          method: 'GET',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString('utf8'));

        if (jres && jres.hasOwnProperty('results')) {
          const items = jres['results'];
          for (let i=0; i<items.length; i++) {
            let item = items[i];
            if(item['data'] && item['data']['properties']) {
              let line = {'classification_id': item["data"]["properties"]["classification_id"], 'classification_name': item["data"]["properties"]["classification_name"], 'classification_description': item["data"]["properties"]["classification_description"], 'category_id': item["data"]["properties"]["category_id"], 'location': item["data"]["properties"]["location"], 'document_generation': item["data"]["properties"]["document_generation"], 'required': item["data"]["properties"]["required"], 'template_id': item["data"]["properties"]["template_id"]};
              retval.push(line);
            }
          }
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in businessworkspace_smartdoctypes_get() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`businessworkspace_smartdoctypes_get() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Get available Smart Document Types of Business Workspace
   * 
   * @param {*} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {*} bwsId The Node ID of the Business Workspace
   * @param {*} categoryId The Node ID of the Category which is applied. Get it from businessworkspace_smartdoctypes_get()
   * @returns {Array} form fields of the category definition: [ { data: { category_id: 6002, '6002_2': null }, options: { fields: [Object], form: [Object] }, schema: { properties: [Object], type: 'object' } } ]
   */
  businessworkspace_categorydefinition_for_upload_get = async(baseUrlCS, bwsId, categoryId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`businessworkspace_categorydefinition_for_upload_get() start: baseUrlCS=${baseUrlCS}, bwsId=${bwsId}, categoryId=${categoryId}`);
    }

    let retval = [];
    let apiendpoint = `api/v1/forms/nodes/categories/create`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = { 'id': bwsId, 'category_id': categoryId };

      let get_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint + ('?' + get_data) || '',
          method: 'GET',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString('utf8'));

        if (jres && jres.hasOwnProperty('forms')) {
          retval = jres['forms'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in businessworkspace_categorydefinition_for_upload_get() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`businessworkspace_categorydefinition_for_upload_get() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Upload Document into HR workspace from a Local File. Used in CS Version 24.2 and prior.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {string} logicalSystem The Logical System customized under the Connections to Business Applications (External Systems). I.e. SuccessFactors
   * @param {string} boType The Business Object Type. I.e. sfsf:user or BUS1065
   * @param {string} boId The Business Object ID. I.e. 2100000
   * @param {string} localFolder The local path to store the file.
   * @param {string} localFileName The local file name of the document.
   * @param {string} remoteFileName The remote file name of the document.
   * @param {string} documentType The document type (name of classification) of the document. I.e. 'Application Document'
   * @param {Date} dateOfOrigin The date of origin of the document.
   * @returns {number} the new node id of the uploaded document
   */
  businessworkspace_hr_upload_file_depricated = async(baseUrlCS, logicalSystem, boType, boId, localFolder, localFileName, remoteFileName, documentType, dateOfOrigin) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`businessworkspace_hr_upload_file_depricated() start: baseUrlCS=${baseUrlCS}, logicalSystem=${logicalSystem}, boType=${boType}, boId=${boId}, localFolder=${localFolder}, localFileName=${localFileName}, remoteFileName=${remoteFileName}, documentType=${documentType}, dateOfOrigin=${dateOfOrigin}`);
    }

    let retval = -1;
    let apiendpoint = `api/v2/businessobjects/${logicalSystem}/${boType}/${boId}/hrdocuments`;
    try {
      let filePath = path.join(localFolder, localFileName);
      let contentStream = fs.createReadStream(filePath);
      let contentLength = fs.statSync(filePath).size;

      let baseUrl = this._checkUrl(baseUrlCS);

      let params = { 'doc_type': documentType, 'date_of_origin': dateOfOrigin.toISOString() };

      //let files = [{ 'param': 'file', 'filename': remoteFileName, 'mimetype': 'application/octet-stream', 'data': fs.readFileSync(path.join(localFolder, localFileName)) }];
      let files = [];

      let post_data = this._getFormData(params, files);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'multipart/form-data; boundary=' + post_data['boundary']
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'POST',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        // res = await this.doCallHttps(post_data['formdata'], options);
        res = await this.doUploadHttps(contentStream, contentLength, 'file', remoteFileName, 'application/octet-stream', post_data['boundary'], post_data['formdata'], options);
      } else {
        // res = await this.doCallHttp(post_data['formdata'], options);
        res = await this.doUploadHttp(contentStream, contentLength, 'file', remoteFileName, 'application/octet-stream', post_data['boundary'], post_data['formdata'], options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results']['nodeID'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in businessworkspace_hr_upload_file_depricated() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`businessworkspace_hr_upload_file_depricated() finished: ${retval}`);
    }
    return retval;
  }

  /**
   * Upload Document into HR workspace as Byte Array. Used in CS Version 24.2 and prior.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {string} logicalSystem The Logical System customized under the Connections to Business Applications (External Systems). I.e. SuccessFactors
   * @param {string} boType The Business Object Type. I.e. sfsf:user or BUS1065
   * @param {string} boId The Business Object ID. I.e. 2100000
   * @param {Buffer} contentBuffer The bytearray containing the file's content.
   * @param {string} remoteFileName The remote file name of the document.
   * @param {string} documentType The document type (name of classification) of the document. I.e. 'Application Document'
   * @param {Date} dateOfOrigin The date of origin of the document.
   * @returns {number} the new node id of the uploaded document
   */
  businessworkspace_hr_upload_bytes_depricated = async(baseUrlCS, logicalSystem, boType, boId, contentBuffer, remoteFileName, documentType, dateOfOrigin) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`businessworkspace_hr_upload_bytes_depricated() start: baseUrlCS=${baseUrlCS}, logicalSystem=${logicalSystem}, boType=${boType}, boId=${boId}, contentBuffer=${contentBuffer}, remoteFileName=${remoteFileName}, documentType=${documentType}, dateOfOrigin=${dateOfOrigin}`);
    }

    let retval = -1;
    let apiendpoint = `api/v2/businessobjects/${logicalSystem}/${boType}/${boId}/hrdocuments`;
    try {
      let contentStream = Readable.from(contentBuffer);
      let contentLength = contentBuffer.length;

      let baseUrl = this._checkUrl(baseUrlCS);

      let params = { 'doc_type': documentType, 'date_of_origin': dateOfOrigin.toISOString() };

      //let files = [{ 'param': 'file', 'filename': remoteFileName, 'mimetype': 'application/octet-stream', 'data': contentBuffer }];
      let files = [];

      let post_data = this._getFormData(params, files);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'multipart/form-data; boundary=' + post_data['boundary']
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'POST',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        // res = await this.doCallHttps(post_data['formdata'], options);
        res = await this.doUploadHttps(contentStream, contentLength, 'file', remoteFileName, 'application/octet-stream', post_data['boundary'], post_data['formdata'], options);
      } else {
        // res = await this.doCallHttp(post_data['formdata'], options);
        res = await this.doUploadHttp(contentStream, contentLength, 'file', remoteFileName, 'application/octet-stream', post_data['boundary'], post_data['formdata'], options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results']['nodeID'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in businessworkspace_hr_upload_bytes_depricated() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`businessworkspace_hr_upload_bytes_depricated() finished: ${retval}`);
    }
    return retval;
  }

  /**
   * Upload Document into HR workspace from a Local File. Used in CS Version 24.3 and later.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} bwsId The NodeID of the Business Workspace.
   * @param {string} localFolder The local path to store the file.
   * @param {string} localFileName The local file name of the document.
   * @param {string} remoteFileName The remote file name of the document.
   * @param {number} classificationId The Node ID of the document type (ID of classification) of the document.
   * @param {number} categoryId The Node ID of the category (containing the Date Of Origin) of the document.
   * @param {object} category The category containing usually the date of origin of the document. I.e. { "6002_2": "2025-02-15T00:00:00Z"}
   * @returns {number} the new node id of the uploaded document
   */
  businessworkspace_hr_upload_file = async(baseUrlCS, bwsId, localFolder, localFileName, remoteFileName, classificationId, categoryId, category) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`businessworkspace_hr_upload_file() start: baseUrlCS=${baseUrlCS}, bwsId=${bwsId}, localFolder=${localFolder}, localFileName=${localFileName}, remoteFileName=${remoteFileName}, classificationId=${classificationId}, categoryId=${categoryId}, category=${category}`);
    }

    let retval = -1;
    let apiendpoint = `api/v2/businessworkspace/preview`;
    try {
      let filePath = path.join(localFolder, localFileName);
      let contentStream = fs.createReadStream(filePath);
      let contentLength = fs.statSync(filePath).size;

      let baseUrl = this._checkUrl(baseUrlCS);

      let params = { 'bw_id': bwsId };

      //let files = [{ 'param': 'file', 'filename': remoteFileName, 'mimetype': 'application/octet-stream', 'data': fs.readFileSync(path.join(localFolder, localFileName)) }];
      let files = [];

      let post_data = this._getFormData(params, files);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'multipart/form-data; boundary=' + post_data['boundary']
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'POST',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        // res = await this.doCallHttps(post_data['formdata'], options);
        res = await this.doUploadHttps(contentStream, contentLength, 'file', remoteFileName, 'application/octet-stream', post_data['boundary'], post_data['formdata'], options);
      } else {
        // res = await this.doCallHttp(post_data['formdata'], options);
        res = await this.doUploadHttp(contentStream, contentLength, 'file', remoteFileName, 'application/octet-stream', post_data['boundary'], post_data['formdata'], options);
      }

      if (res['statusCode'] === 200) {
        let jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results']['docNodeId'];
        }

        if (retval > 0) {
          apiendpoint = `api/v2/businessworkspace/${bwsId}/postupload`;

          params = {'docNodeId': retval, 'classification_id': classificationId, 'document_name': remoteFileName };

          post_data = this._getUrlEncodedData(params);
          req_headers = {
                'User-Agent': this._userAgent,
                'Content-Type': 'application/x-www-form-urlencoded'
          };

          req_headers = this._addAuthHeader(req_headers);

          options = {
              hostname: baseUrl['host'],
              port: baseUrl['port'],
              path: baseUrl['path'] + apiendpoint,
              method: 'PUT',
              headers: req_headers
          };

          res = "";
          if (baseUrl['protocol'] === "https") {
            res = await this.doCallHttps(post_data, options);
          } else {
            res = await this.doCallHttp(post_data, options);
          }

          if (res['statusCode'] === 200) {
            jres = JSON.parse(res['body'].toString("utf8"));

            if (jres && jres.hasOwnProperty('results') && jres['results'].hasOwnProperty('ok') && jres['results'].hasOwnProperty('errMsg') && jres['results']['ok'] &&  jres['results']['errMsg']) {
              if (this._logger === LogType.DEBUG) {
                console.debug(`businessworkspace_hr_upload_file() postupload - successfully applied classification`);
              } else {
                let error_message2 = `Error in businessworkspace_hr_upload_file() postupload -> the classification was not applied successfully: ${jres['results']['errMsg']}`;
                console.error(error_message2);

                if (retval > 0) {
                  try {
                    // clean up 999 Inbox folder
                    await this.node_delete(baseUrlCS, retval);
                    retval = -1;
                  } catch(innerErr3) {

                    if (innerErr3 instanceof LoginTimeoutException) {
                      throw innerErr3;
                    } else {
                      let error_message3 = `Error in businessworkspace_hr_upload_file() postupload - cleanup failed: the file could not deleted from 999 Inbox: ${innerErr3}.`;
                      console.error(error_message3);
                    }
                  }
                }
                throw new Error(error_message2);
              }
            }

            if (this._logger === LogType.DEBUG) {
              console.debug(`businessworkspace_hr_upload_file() postupload finished: ${JSON.stringify(jres)}`);
            }

            if (category) {
              res = await this.node_category_update(baseUrlCS, retval, categoryId, category);
              if (this._logger === LogType.DEBUG) {
                console.debug(`businessworkspace_hr_upload_file() -> node_category_add() finished: ${JSON.stringify(res)}`);
              }
            }
          } else if(res['statusCode'] === 401) {
            throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
          } else {
            throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
          }
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in businessworkspace_hr_upload_file() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`businessworkspace_hr_upload_file() finished: ${retval}`);
    }
    return retval;
  }

  /**
   * Upload Document into HR workspace as Byte Array. Used in CS Version 24.3 and later.
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} bwsId The NodeID of the Business Workspace.
   * @param {Buffer} localFolder The bytearray containing the file's content.
   * @param {string} remoteFileName The remote file name of the document.
   * @param {number} classificationId The Node ID of the document type (ID of classification) of the document.
   * @param {number} categoryId The Node ID of the category (containing the Date Of Origin) of the document.
   * @param {object} category The category containing usually the date of origin of the document. I.e. { "6002_2": "2025-02-15T00:00:00Z"}
   * @returns {number} the new node id of the uploaded document
   */
  businessworkspace_hr_upload_bytes = async(baseUrlCS, bwsId, contentBuffer, remoteFileName, classificationId, categoryId, category) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`businessworkspace_hr_upload_bytes() start: baseUrlCS=${baseUrlCS}, bwsId=${bwsId}, contentBuffer=${contentBuffer}, remoteFileName=${remoteFileName}, classificationId=${classificationId}, categoryId=${categoryId}, category=${category}`);
    }

    let retval = -1;
    let apiendpoint = `api/v2/businessworkspace/preview`;
    try {
      let contentStream = Readable.from(contentBuffer);
      let contentLength = contentBuffer.length;

      let baseUrl = this._checkUrl(baseUrlCS);

      let params = { 'bw_id': bwsId };

      //let files = [{ 'param': 'file', 'filename': remoteFileName, 'mimetype': 'application/octet-stream', 'data': fs.readFileSync(path.join(localFolder, localFileName)) }];
      let files = [];

      let post_data = this._getFormData(params, files);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'multipart/form-data; boundary=' + post_data['boundary']
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'POST',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        // res = await this.doCallHttps(post_data['formdata'], options);
        res = await this.doUploadHttps(contentStream, contentLength, 'file', remoteFileName, 'application/octet-stream', post_data['boundary'], post_data['formdata'], options);
      } else {
        // res = await this.doCallHttp(post_data['formdata'], options);
        res = await this.doUploadHttp(contentStream, contentLength, 'file', remoteFileName, 'application/octet-stream', post_data['boundary'], post_data['formdata'], options);
      }

      if (res['statusCode'] === 200) {
        let jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results']['docNodeId'];
        }

        if (retval > 0) {
          apiendpoint = `api/v2/businessworkspace/${bwsId}/postupload`;

          params = {'docNodeId': retval, 'classification_id': classificationId, 'document_name': remoteFileName };

          post_data = this._getUrlEncodedData(params);
          req_headers = {
                'User-Agent': this._userAgent,
                'Content-Type': 'application/x-www-form-urlencoded'
          };

          req_headers = this._addAuthHeader(req_headers);

          options = {
              hostname: baseUrl['host'],
              port: baseUrl['port'],
              path: baseUrl['path'] + apiendpoint,
              method: 'PUT',
              headers: req_headers
          };

          res = "";
          if (baseUrl['protocol'] === "https") {
            res = await this.doCallHttps(post_data, options);
          } else {
            res = await this.doCallHttp(post_data, options);
          }

          if (res['statusCode'] === 200) {
            jres = JSON.parse(res['body'].toString("utf8"));

            if (jres && jres.hasOwnProperty('results') && jres['results'].hasOwnProperty('ok') && jres['results'].hasOwnProperty('errMsg') && jres['results']['ok'] &&  jres['results']['errMsg']) {
              if (this._logger === LogType.DEBUG) {
                console.debug(`businessworkspace_hr_upload_bytes() postupload - successfully applied classification`);
              } else {
                let error_message2 = `Error in businessworkspace_hr_upload_bytes() postupload -> the classification was not applied successfully: ${jres['results']['errMsg']}`;
                console.error(error_message2);

                if (retval > 0) {
                  try {
                    // clean up 999 Inbox folder
                    await this.node_delete(baseUrlCS, retval);
                    retval = -1;
                  } catch(innerErr3) {

                    if (innerErr3 instanceof LoginTimeoutException) {
                      throw innerErr3;
                    } else {
                      let error_message3 = `Error in businessworkspace_hr_upload_bytes() postupload - cleanup failed: the file could not deleted from 999 Inbox: ${innerErr3}.`;
                      console.error(error_message3);
                    }
                  }
                }
                throw new Error(error_message2);
              }
            }

            if (this._logger === LogType.DEBUG) {
              console.debug(`businessworkspace_hr_upload_bytes() postupload finished: ${JSON.stringify(jres)}`);
            }

            if (category) {
              res = await this.node_category_update(baseUrlCS, retval, categoryId, category);
              if (this._logger === LogType.DEBUG) {
                console.debug(`businessworkspace_hr_upload_file() -> node_category_add() finished: ${JSON.stringify(res)}`);
              }
            }
          } else if(res['statusCode'] === 401) {
            throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
          } else {
            throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
          }
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in businessworkspace_hr_upload_bytes() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`businessworkspace_hr_upload_bytes() finished: ${retval}`);
    }
    return retval;
  }

  /**
   * Apply the Owner Permissions to a Node
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Node ID to update.
   * @param {object} newPerms The new Permissions. I.e. { "permissions":["see","see_contents"] } or { "permissions":["see","see_contents"], "right_id": 1000, "apply_to":0 }
                The allowable values for permissions are:
                "see"
                "see_contents"
                "modify"
                "edit_attributes"
                "add_items"
                "reserve"
                "add_major_version"
                "delete_versions"
                "delete"
                "edit_permissions"

                Apply the change to different levels:
                0 This Item
                1 Sub-Items
                2 This Item and Sub-Items
                3 This Item And Immediate Sub-Items
   * @returns {number} the Node ID which is updated.
   */
  node_permissions_owner_apply = async(baseUrlCS, nodeId, newPerms) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_owner_apply() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, newPerms=${JSON.stringify(newPerms)}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/nodes/${nodeId}/permissions/owner`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = {'body': JSON.stringify(newPerms)};
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'PUT',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres) {
          retval = nodeId;
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_permissions_owner_apply() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_owner_apply() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Delete the Owner Permissions from a Node
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Node ID to update.
   * @returns {number} the Node ID which is updated.
   */
  node_permissions_owner_delete = async(baseUrlCS, nodeId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_owner_delete() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/nodes/${nodeId}/permissions/owner`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'DELETE',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres) {
          retval = nodeId;
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_permissions_owner_delete() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_owner_delete() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Apply the Group Permissions to a Node
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Node ID to update.
   * @param {object} newPerms The new Permissions. I.e. { "permissions":["see","see_contents"] } or { "permissions":["see","see_contents"], "right_id": 1000, "apply_to":0 }
                The allowable values for permissions are:
                "see"
                "see_contents"
                "modify"
                "edit_attributes"
                "add_items"
                "reserve"
                "add_major_version"
                "delete_versions"
                "delete"
                "edit_permissions"

                Apply the change to different levels:
                0 This Item
                1 Sub-Items
                2 This Item and Sub-Items
                3 This Item And Immediate Sub-Items
   * @returns {number} the Node ID which is updated.
   */
  node_permissions_group_apply = async(baseUrlCS, nodeId, newPerms) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_group_apply() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, newPerms=${JSON.stringify(newPerms)}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/nodes/${nodeId}/permissions/group`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = {'body': JSON.stringify(newPerms)};
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'PUT',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres) {
          retval = nodeId;
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_permissions_group_apply() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_group_apply() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Delete the Group Permissions from a Node
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Node ID to update.
   * @returns {number} the Node ID which is updated.
   */
  node_permissions_group_delete = async(baseUrlCS, nodeId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_group_delete() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/nodes/${nodeId}/permissions/group`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'DELETE',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres) {
          retval = nodeId;
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_permissions_group_delete() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_group_delete() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Apply the Public Permissions to a Node
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Node ID to update.
   * @param {object} newPerms The new Permissions. I.e. { "permissions":["see","see_contents"] } or { "permissions":["see","see_contents"], "apply_to":0 }
                The allowable values for permissions are:
                "see"
                "see_contents"
                "modify"
                "edit_attributes"
                "add_items"
                "reserve"
                "add_major_version"
                "delete_versions"
                "delete"
                "edit_permissions"

                Apply the change to different levels:
                0 This Item
                1 Sub-Items
                2 This Item and Sub-Items
                3 This Item And Immediate Sub-Items
   * @returns {number} the Node ID which is updated.
   */
  node_permissions_public_apply = async(baseUrlCS, nodeId, newPerms) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_public_apply() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, newPerms=${JSON.stringify(newPerms)}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/nodes/${nodeId}/permissions/public`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = {'body': JSON.stringify(newPerms)};
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'PUT',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres) {
          retval = nodeId;
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_permissions_public_apply() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_public_apply() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Delete the Public Permissions from a Node
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Node ID to update.
   * @returns {number} the Node ID which is updated.
   */
  node_permissions_public_delete = async(baseUrlCS, nodeId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_public_delete() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/nodes/${nodeId}/permissions/public`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'DELETE',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres) {
          retval = nodeId;
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_permissions_public_delete() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_public_delete() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Add new Custom Permissions to a Node
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Node ID to update.
   * @param {Array} newPerms The new Permissions. I.e. [{ "permissions":["see","see_contents"], "right_id": 1001 }] or [{ "permissions":["see","see_contents"], "right_id": 1001, "apply_to":0 }]
                The allowable values for permissions are:
                "see"
                "see_contents"
                "modify"
                "edit_attributes"
                "add_items"
                "reserve"
                "add_major_version"
                "delete_versions"
                "delete"
                "edit_permissions"

                Apply the change to different levels:
                0 This Item
                1 Sub-Items
                2 This Item and Sub-Items
                3 This Item And Immediate Sub-Items
   * @returns {number} the Node ID which is updated.
   */
  node_permissions_custom_apply = async(baseUrlCS, nodeId, newPerms) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_custom_apply() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, newPerms=${JSON.stringify(newPerms)}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/nodes/${nodeId}/permissions/custom/bulk`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = {'permissions_array': JSON.stringify(newPerms)};
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'POST',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres) {
          retval = nodeId;
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_permissions_custom_apply() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_custom_apply() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Update the Custom Permissions of a specific Right ID to a Node
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Node ID to update.
   * @param {object} newPerms The new Permissions. I.e. { "permissions":["see","see_contents"] } or { "permissions":["see","see_contents"], "apply_to":0 }
                The allowable values for permissions are:
                "see"
                "see_contents"
                "modify"
                "edit_attributes"
                "add_items"
                "reserve"
                "add_major_version"
                "delete_versions"
                "delete"
                "edit_permissions"

                Apply the change to different levels:
                0 This Item
                1 Sub-Items
                2 This Item and Sub-Items
                3 This Item And Immediate Sub-Items
   * @returns {number} the Node ID which is updated.
   */
  node_permissions_custom_update = async(baseUrlCS, nodeId, rightId, newPerms) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_custom_update() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, rightId=${rightId}, newPerms=${JSON.stringify(newPerms)}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/nodes/${nodeId}/permissions/custom/${rightId}`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = {'body': JSON.stringify(newPerms)};
      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'PUT',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres) {
          retval = nodeId;
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_permissions_custom_update() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_custom_update() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Delete the Custom Permissions of a specific Right ID from a Node
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The Node ID to update.
   * @param {number} rightId The Content Server User or Group ID to update.
   * @returns {number} the Node ID which is updated.
   */
  node_permissions_custom_delete = async(baseUrlCS, nodeId, rightId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_custom_delete() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, rightId=${rightId}`);
    }

    let retval = {};
    let apiendpoint = `api/v2/nodes/${nodeId}/permissions/custom/${rightId}`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'DELETE',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres) {
          retval = nodeId;
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in node_permissions_custom_delete() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`node_permissions_custom_delete() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Call WebReport by Nickname and pass Parameters by POST method (form-data)
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {string} nickname The Nickname of the WebReport.
   * @param {object} params The Parameters to be passed to the WebReport. I.e. { "p_name": "name", "p_desc": "description" }
   * @returns {string} the Result of the WebReport
   */
  webreport_nickname_call = async(baseUrlCS, nickname, params) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`webreport_nickname_call() start: baseUrlCS=${baseUrlCS}, nickname=${nickname}, params=${JSON.stringify(params)}`);
    }

    let retval = "";
    let apiendpoint = `api/v1/webreports/${nickname}`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      if (!params.hasOwnProperty('format')) {
        params['format'] = 'webreport';
      }

      let post_data = this._getFormData(params, []);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'multipart/form-data; boundary=' + post_data['boundary'],
            'Content-Length': post_data['formdata'].length
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'POST',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data['formdata'], options);
      } else {
        res = await this.doCallHttp(post_data['formdata'], options);
      }

      if (res['statusCode'] === 200) {
        retval = res['body'].toString("utf8");
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in webreport_nickname_call() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`webreport_nickname_call() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Call WebReport by NodeID and pass Parameters by POST method (form-data)
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} nodeId The NodeID of the WebReport.
   * @param {object} params The Parameters to be passed to the WebReport. I.e. { "p_name": "name", "p_desc": "description" }
   * @returns {string} the Result of the WebReport
   */
  webreport_nodeid_call = async(baseUrlCS, nodeId, params) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`webreport_nodeid_call() start: baseUrlCS=${baseUrlCS}, nodeId=${nodeId}, params=${JSON.stringify(params)}`);
    }

    let retval = "";
    let apiendpoint = `api/v1/nodes/${nodeId}/output`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      if (!params.hasOwnProperty('format')) {
        params['format'] = 'webreport';
      }

      let post_data = this._getFormData(params, []);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'multipart/form-data; boundary=' + post_data['boundary'],
            'Content-Length': post_data['formdata'].length
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'POST',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data['formdata'], options);
      } else {
        res = await this.doCallHttp(post_data['formdata'], options);
      }

      if (res['statusCode'] === 200) {
        retval = res['body'].toString("utf8");
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in webreport_nodeid_call() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`webreport_nodeid_call() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Get available Document Workflows
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} parentId The Node ID of the Parent in which the Document is stored.
   * @param {number} documentId The Node ID of the Document for which the workflow is looked up for.
   * @returns {Array} available workflows
   */
  workflows_document_get_available = async(baseUrlCS, parentId, documentId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`workflows_document_get_available() start: baseUrlCS=${baseUrlCS}, parentId=${parentId}, documentId=${documentId}`);
    }

    let retval = [];
    let apiendpoint = `api/v2/docworkflows`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = { 'doc_id': documentId, 'parent_id': parentId };

      let get_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint + ('?' + get_data) || '',
          method: 'GET',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString('utf8'));

        if (jres && jres.hasOwnProperty('results') && jres['results'].hasOwnProperty('data')) {
          retval = jres['results']['data'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in workflows_document_get_available() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`workflows_document_get_available() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Create a new Draft Process for the Document Workflow
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} workflowId The ID of the workflow to be created.
   * @param {string} documentIds The Node IDs of the Documents for which the workflow is created. I.e. "130480" or "130480,132743"
   * @returns {object} Result of the draftprocess creation. I.e. { "draftprocess_id": 134043, "workflow_type": "1_1" }
   */
  workflows_document_draft_create = async(baseUrlCS, workflowId, documentIds) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`workflows_document_draft_create() start: baseUrlCS=${baseUrlCS}, workflowId=${workflowId}, documentIds=${documentIds}`);
    }

    let retval = { };
    let apiendpoint = `api/v2/draftprocesses`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let data = { 'workflow_id': workflowId, 'doc_ids': documentIds };
      let params = { 'body': JSON.stringify(data) };

      let post_data = this._getFormData(params, []);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'multipart/form-data; boundary=' + post_data['boundary'],
            'Content-Length': post_data['formdata'].length
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'POST',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data['formdata'], options);
      } else {
        res = await this.doCallHttp(post_data['formdata'], options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString('utf8'));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in workflows_document_draft_create() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`workflows_document_draft_create() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Get form for the Draft Process
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} draftId The ID of the Draft Process.
   * @returns {object} Result of the form information of the draftprocess. I.e. { 'data': {...}, 'forms': [...] }
   */
  workflows_document_draft_form_get = async(baseUrlCS, draftId) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`workflows_document_draft_form_get() start: baseUrlCS=${baseUrlCS}, draftId=${draftId}`);
    }

    let retval = { };
    let apiendpoint = `api/v1/forms/draftprocesses/update`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let params = { 'draftprocess_id': draftId };

      let get_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/json'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint + ('?' + get_data) || '',
          method: 'GET',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(null, options);
      } else {
        res = await this.doCallHttp(null, options);
      }

      if (res['statusCode'] === 200) {
        retval = JSON.parse(res['body'].toString('utf8'));
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in workflows_document_draft_form_get() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`workflows_document_draft_form_get() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }

  /**
   * Initiate the Draft Process
   * 
   * @param {string} baseUrlCS The URL to be called. I.e. http://content-server/otcs/cs.exe
   * @param {number} draftId The ID of the Draft Process.
   * @param {string} comment The comment to be applied to the Initiation Draft Process.
   * @returns {object} Result of the draftprocess initiation. I.e. {'custom_message': None, 'process_id': 134687, 'WorkID': None, 'WRID': None}
   */
  workflows_document_draft_initiate = async(baseUrlCS, draftId, comment) => {
    if (this._logger === LogType.DEBUG) {
      console.debug(`workflows_document_draft_initiate() start: baseUrlCS=${baseUrlCS}, draftId=${draftId}, comment=${comment}`);
    }

    let retval = { };
    let apiendpoint = `api/v2/draftprocesses/${draftId}`;
    try {
      let baseUrl = this._checkUrl(baseUrlCS);

      let data = { 'action': 'Initiate', 'comment': comment };
      let params = {'body': JSON.stringify(data)};

      let post_data = this._getUrlEncodedData(params);
      let req_headers = {
            'User-Agent': this._userAgent,
            'Content-Type': 'application/x-www-form-urlencoded'
      };

      req_headers = this._addAuthHeader(req_headers);

      let options = {
          hostname: baseUrl['host'],
          port: baseUrl['port'],
          path: baseUrl['path'] + apiendpoint,
          method: 'PUT',
          headers: req_headers
      };

      let res = "";
      if (baseUrl['protocol'] === "https") {
        res = await this.doCallHttps(post_data, options);
      } else {
        res = await this.doCallHttp(post_data, options);
      }

      if (res['statusCode'] === 200) {
        const jres = JSON.parse(res['body'].toString("utf8"));

        if (jres && jres.hasOwnProperty('results')) {
          retval = jres['results'];
        }
      } else if(res['statusCode'] === 401) {
        throw new LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      } else {
        throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
      }
    } catch(innerErr) {
      if (innerErr instanceof LoginTimeoutException) {
        throw innerErr;
      } else {
        let error_message = `Error in workflows_document_draft_initiate() ${this._baseUrlDict['path'] + apiendpoint}: ${innerErr.response?.status || ''} ${innerErr.response?.data || innerErr.message}`;
        console.error(error_message);
        throw new Error(error_message);
      }
    }

    if (this._logger === LogType.DEBUG) {
      console.debug(`workflows_document_draft_initiate() finished: ${JSON.stringify(retval)}`);
    }
    return retval;
  }
}

module.exports = {
  CSRestAPI,
  LoginType,
  LogType,
  LoginTimeoutException
};
