--[[
Copyright 2015 Rackspace

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS-IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
--]]
local JSON = require('json')
local Object = require('core').Object
local Error = require('core').Error
local request = require('request').request

local Client = Object:extend()
function Client:initialize(authUrl, options)
  self.authUrl = authUrl
  self.username = options.username
  self.apikey = options.apikey
  self.password = options.password
  self.extraArgs = options.extraArgs or {}
  self.mfaCallback = options.mfaCallback
  self._token = nil
  self._tokenExpires = nil
  self._tenantId = nil
  self._serviceCatalog = {}
end

function Client:setMFACallback(callback)
  self.mfaCallback = callback
end

function Client:_updateToken(callback)

  local iter
  iter = function(mfaOptions)
    local body, options
    local headers = {
      {'Content-Type', 'application/json'},
    }

    if mfaOptions then
      table.insert(headers, {'X-SessionId', mfaOptions and mfaOptions.session_id })
      body = {
        ['auth'] = {
          ['RAX-AUTH:passcodeCredentials'] = {
            ['passcode'] = mfaOptions.passcode
          }
        }
      }
    elseif self.password then
      body = {
        ['auth'] = {
          ['passwordCredentials'] = {
            ['username'] = self.username,
            ['password'] = self.password
          }
        }
      }
    else
      body = {
        ['auth'] = {
          ['RAX-KSKEY:apiKeyCredentials'] = {
            ['username'] = self.username,
            ['apiKey'] = self.apikey
          }
        }
      }
    end

    body = JSON.stringify(body)
    table.insert(headers, {'Content-Length', #body})

    options = {
      url = self.authUrl,
      headers = headers,
      method = 'POST',
      body = body
    }

    local function handleMFAResponse(res)
      if res.headers['www-authenticate'] then
        local auth = res.headers['www-authenticate']
        local sidx = auth:find('\'')
        local eidx = auth:find('\'', sidx + 1)
        local mfa_options = {}
        mfa_options.session_id = auth:sub(sidx + 1, eidx - 1)
        mfa_options.passcode = nil
        if self.mfaCallback then
          self.mfaCallback(function(err, passcode)
            if err then
              callback(err)
            else
              mfa_options.passcode = passcode
              iter(mfa_options)
            end
          end)
        end
      else
        callback(Error:new('Not authenticated'))
      end
    end

    local function handleTokenResponse(res)
      local chunks = {}
      res:on('data', function(chunk)
        table.insert(chunks, chunk)
      end)
      res:on('end', function()
        local payload, newToken, newExpires
        local results  = {
          xpcall(function()
            return JSON.parse(table.concat(chunks))
          end, function(err)
            return err
          end)
        }
        -- protected call errored out
        if not results[1] then
          return callback(results[1])
        end

        payload = results[2]
        if payload.access then
          newToken = payload.access.token.id
          newExpires = payload.access.token.expires
        else
          callback(Error:new('Invalid response from auth server'))
          return
        end

        self._token = newToken
        self._tokenExpires = newExpires
        self._serviceCatalog = payload.access.serviceCatalog

        callback(nil, self._token)
      end)
    end

    local function handleResponse(err, res)
      if err then
        return callback(err)
      end

      if res.statusCode == 400 then
        handleMFAResponse(res)
      else
        handleTokenResponse(res)
      end
    end

  if process.env.HTTP_PROXY then
    options.proxy = process.env.HTTP_PROXY
  elseif process.env.HTTPS_PROXY then
    options.proxy = process.env.HTTPS_PROXY
  end

    request(options, handleResponse)
  end

  iter()
end

function Client:tenantIdAndToken(providerName, callback)
  self:_updateToken(function(err, token)
    if err then
      callback(err)
      return
    end
    for i, _ in ipairs(self._serviceCatalog) do
      local item = self._serviceCatalog[i]
      if item.name == providerName then
        if #item.endpoints == 0 then
          error('Endpoints should be > 0')
        end
        self._tenantId = item.endpoints[1].tenantId
        break
      end
    end
    callback(nil, { token = self._token, expires = self._tokenExpires, tenantId = self._tenantId })
  end)
end

exports.Client = Client
