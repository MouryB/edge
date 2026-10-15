// "Sign in with ChatGPT" plan usage: the OAuth round trip through a real
// loopback listener, token refresh, and the coach's one provider POST routed
// to OpenAI's streaming-only Responses route with the plan's access token.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:http/testing.dart';
import 'package:openstrap_edge/coach/coach_chatgpt.dart';
import 'package:openstrap_edge/coach/coach_config.dart';
import 'package:openstrap_edge/coach/coach_engine.dart';
import 'package:shared_preferences/shared_preferences.dart';

// Flutter's test binding fakes HttpClient; this one really reaches loopback.
class _RealHttpOverrides extends HttpOverrides {}

String _jwt(Map<String, Object?> claims) {
  String b64(Object o) => base64Url.encode(utf8.encode(jsonEncode(o))).replaceAll('=', '');
  return '${b64({'alg': 'RS256'})}.${b64(claims)}.sig';
}

String _idToken(String clientId, String nonce, {String iss = kChatGptIssuer, int? exp}) =>
    _jwt({
      'iss': iss,
      'aud': clientId,
      'sub': 'user-1',
      'email': 'me@example.com',
      'nonce': nonce,
      'exp': exp ?? DateTime.now().add(const Duration(hours: 1)).millisecondsSinceEpoch ~/ 1000,
    });

const _fullScope = 'chatgpt.tokens.use.direct email offline_access openid profile resource.invoke';

ChatGptSession _session({DateTime? expiresAt, String scope = _fullScope}) => ChatGptSession(
      sub: 'user-1',
      email: 'me@example.com',
      idToken: 'old-id-token',
      accessToken: 'at-1',
      refreshToken: 'rt-1',
      scope: scope,
      expiresAt: expiresAt ?? DateTime.now().add(const Duration(hours: 1)),
    );

String _sse(List<Map<String, Object?>> events) =>
    events.map((e) => 'event: ${e['type']}\ndata: ${jsonEncode(e)}\n\n').join();

Map<String, Object?> _completed(String text) => {
      'type': 'response.completed',
      'response': {
        'status': 'completed',
        'output': [
          {
            'type': 'message',
            'status': 'completed',
            'role': 'assistant',
            'content': [
              {'type': 'output_text', 'text': text, 'annotations': []},
            ],
          },
        ],
      },
    };

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('plugins.it_nomads.com/flutter_secure_storage');
  late Map<String, String> keychain;

  setUp(() {
    keychain = {};
    SharedPreferences.setMockInitialValues({});
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      final args = (call.arguments as Map?) ?? const {};
      switch (call.method) {
        case 'read':
          return keychain[args['key']];
        case 'write':
          keychain[args['key'] as String] = args['value'] as String;
        case 'delete':
          keychain.remove(args['key']);
        case 'containsKey':
          return keychain.containsKey(args['key']);
      }
      return null;
    });
  });

  tearDown(() => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
      .setMockMethodCallHandler(channel, null));

  test('PKCE challenge is the RFC 7636 S256 transform', () {
    expect(chatGptCodeChallenge('dBjftJeZ4CVP-mJ92K9qn6MWHFJM1yN_GgcsRmJN0_w'),
        'BCCYQ8sMKFQG5yknl8BJ9-8mva0FhJQJZSboXfUVfsc');
  });

  group('sign-in', () {
    late List<Map<String, String>> tokenForms;
    late ChatGptAuth auth;
    late http.Client loopback;

    setUp(() {
      tokenForms = [];
      loopback = IOClient(_RealHttpOverrides().createHttpClient(null));
      addTearDown(loopback.close);
    });

    /// Plays the browser: first a stray hit with the wrong state, which must
    /// not end the sign-in, then the real redirect.
    Future<bool> browser(Uri authorize, {String? clientId, String? error}) async {
      final q = authorize.queryParameters;
      final redirect = Uri.parse(q['redirect_uri']!);
      expect(redirect.host, '127.0.0.1');
      expect(redirect.path, '/auth/callback');
      final stray = await loopback.get(redirect.replace(queryParameters: {'state': 'nope', 'code': 'x'}));
      expect(stray.statusCode, 400);
      unawaited(loopback.get(redirect.replace(queryParameters: {
        'state': q['state']!,
        if (error != null) 'error': error else 'code': 'code-1',
        'client_id': ?clientId,
      })));
      return true;
    }

    ChatGptAuth makeAuth(String Function() nonce) => ChatGptAuth(
          client: MockClient((req) async {
            expect(req.url.toString(), '$kChatGptIssuer/api/accounts/oauth/token');
            tokenForms.add(req.bodyFields);
            return http.Response(
              jsonEncode({
                'access_token': 'at-1',
                'refresh_token': 'rt-1',
                'id_token': _idToken(req.bodyFields['client_id']!, nonce()),
                'scope': _fullScope,
                'expires_in': 3600,
              }),
              200,
            );
          }),
        );

    test('registers, exchanges the code, and signs back in to the same registration', () async {
      late Uri first, second;
      auth = makeAuth(() => (second.hasQuery ? second : first).queryParameters['nonce']!);
      second = Uri();
      expect(
        await auth.signIn((u) {
          first = u;
          return browser(u, clientId: 'oaiapp_1');
        }),
        isTrue,
      );
      final q = first.queryParameters;
      expect(q['client_id'], 'dynamic_agent_client');
      expect(q['agent_name_hint'], 'OpenStrap Edge');
      expect(q['ext_agent_host_id'], startsWith('urn:uuid:'));
      expect(q['scope']!.split(' '), containsAll(['offline_access', 'resource.invoke', kChatGptPlanScope]));
      expect(q['resource'], kChatGptApiBase);
      expect(q['code_challenge_method'], 'S256');
      expect(tokenForms.single, containsPair('client_id', 'oaiapp_1'));
      expect(tokenForms.single, containsPair('grant_type', 'authorization_code'));
      expect(tokenForms.single, containsPair('redirect_uri', q['redirect_uri']));
      expect(chatGptCodeChallenge(tokenForms.single['code_verifier']!), q['code_challenge']);
      expect(auth.sharing, isTrue);
      expect(auth.session!.email, 'me@example.com');

      // Returning sign-in: the saved client id and host id, no name hint.
      expect(
        await auth.signIn((u) {
          second = u;
          return browser(u);
        }),
        isFalse,
      );
      expect(second.queryParameters['client_id'], 'oaiapp_1');
      expect(second.queryParameters['ext_agent_host_id'], q['ext_agent_host_id']);
      expect(second.queryParameters.containsKey('agent_name_hint'), isFalse);
      expect(second.queryParameters['id_token_hint'], isNotNull);
    });

    test('a declined consent ends sign-in without a token exchange', () async {
      auth = makeAuth(() => '');
      await expectLater(
        auth.signIn((u) => browser(u, error: 'access_denied')),
        throwsA(isA<ChatGptException>().having((e) => e.message, 'message', contains('cancelled'))),
      );
      expect(tokenForms, isEmpty);
      expect(auth.signedIn, isFalse);
    });
  });

  test('closing the browser can be cancelled instead of waiting it out', () async {
    final auth = ChatGptAuth(client: MockClient((_) async => fail('no token exchange')));
    await expectLater(
      auth.signIn((_) async {
        auth.cancelSignIn(); // the user gave up while the page was up
        return true;
      }),
      throwsA(isA<ChatGptException>().having((e) => e.message, 'message', contains('cancelled'))),
    );
  });

  test('ID token claims are checked', () {
    final good = _idToken('oaiapp_1', 'n1');
    expect(chatGptIdentity(good, clientId: 'oaiapp_1', nonce: 'n1').sub, 'user-1');
    for (final (token, client, nonce) in [
      (good, 'oaiapp_1', 'other-nonce'),
      (good, 'oaiapp_2', 'n1'),
      (_idToken('oaiapp_1', 'n1', iss: 'https://evil.example'), 'oaiapp_1', 'n1'),
      (_idToken('oaiapp_1', 'n1', exp: 1), 'oaiapp_1', 'n1'),
      ('garbage', 'oaiapp_1', 'n1'),
    ]) {
      expect(() => chatGptIdentity(token, clientId: client, nonce: nonce),
          throwsA(isA<ChatGptException>()));
    }
  });

  group('refresh', () {
    Future<ChatGptAuth> expired(http.Client c) async {
      SharedPreferences.setMockInitialValues({'coach_chatgpt_client_id': 'oaiapp_1'});
      final auth = ChatGptAuth(client: c);
      await auth.debugSetSession(_session(expiresAt: DateTime.now()));
      return auth;
    }

    test('concurrent callers share one rotation', () async {
      final forms = <Map<String, String>>[];
      final auth = await expired(MockClient((req) async {
        forms.add(req.bodyFields);
        return http.Response(
            jsonEncode({'access_token': 'at-2', 'refresh_token': 'rt-2', 'expires_in': 3600}), 200);
      }));
      final tokens = await Future.wait([auth.accessToken(), auth.accessToken()]);
      expect(tokens, ['at-2', 'at-2']);
      expect(forms.single, {
        'grant_type': 'refresh_token',
        'client_id': 'oaiapp_1',
        'refresh_token': 'rt-1',
        'resource': kChatGptApiBase,
      });
      expect(auth.session!.refreshToken, 'rt-2');
      expect(auth.sharing, isTrue, reason: 'scope carried over when not re-sent');
    });

    test('a dead refresh token signs out; a server hiccup does not', () async {
      final hiccup = await expired(MockClient((_) async => http.Response('oops', 502)));
      await expectLater(hiccup.accessToken(), throwsA(isA<ChatGptException>()));
      expect(hiccup.signedIn, isTrue);

      final dead = await expired(
          MockClient((_) async => http.Response(jsonEncode({'error': 'invalid_grant'}), 400)));
      await expectLater(dead.accessToken(), throwsA(isA<ChatGptException>()));
      expect(dead.signedIn, isFalse);
    });
  });

  group('coach requests on the ChatGPT plan', () {
    late CoachConfig cfg;
    setUp(() async {
      cfg = CoachConfig();
      await cfg.chatgpt.debugSetSession(_session());
      await cfg.save(useChatGpt: true, model: 'gpt-6.1-sol');
    });

    Future<Map<String, dynamic>> post(http.Client c) => CoachEngine.postChat(cfg, {
          'model': 'gpt-6.1-sol',
          'messages': [
            {'role': 'system', 'content': 'be brief'},
            {'role': 'user', 'content': 'hi'},
          ],
          'temperature': 0.3,
        }, client: c);

    test('streams to the public Responses API with the plan token', () async {
      expect(cfg.configured, isTrue);
      expect(cfg.isPrivateEndpoint, isFalse, reason: 'health data leaving the phone still asks first');
      late http.Request sent;
      final reply = await post(MockClient((req) async {
        sent = req;
        return http.Response(
          _sse([
            {'type': 'response.output_text.delta', 'delta': 'hel'},
            _completed('hello'),
          ]),
          200,
        );
      }));
      expect(sent.url.toString(), '$kChatGptApiBase/responses');
      expect(sent.headers['Authorization'], 'Bearer at-1');
      final body = jsonDecode(sent.body) as Map;
      expect(body['stream'], isTrue);
      expect(body['store'], isFalse);
      expect(body.containsKey('temperature'), isFalse);
      expect([for (final i in body['input'] as List) i['role']], ['developer', 'user']);
      expect(reply['content'], 'hello');
    });

    test('usage limit, mid-stream failure and a cut-off stream are errors, never a fallback', () async {
      for (final (status, body, expected) in [
        (
          429,
          jsonEncode({'error': {'code': 'subscription_sharing_usage_limit_exceeded'}}),
          'Usage limit reached'
        ),
        (
          200,
          _sse([
            {
              'type': 'response.failed',
              'response': {'error': {'code': 'subscription_sharing_usage_limit_exceeded'}},
            },
          ]),
          'Usage limit reached'
        ),
        (200, _sse([{'type': 'response.output_text.delta', 'delta': 'he'}]), 'ended early'),
      ]) {
        await expectLater(
          post(MockClient((_) async => http.Response(body, status))),
          throwsA(isA<CoachException>().having((e) => e.message, 'message', contains(expected))),
        );
      }
    });

    test('signed in without plan usage is not configured', () async {
      await cfg.chatgpt.debugSetSession(_session(scope: 'openid email profile offline_access'));
      expect(cfg.configured, isFalse);
    });
  });

  test('model list keeps listed slugs in server order', () async {
    final auth = ChatGptAuth(
      client: MockClient((req) async {
        expect(req.headers['Authorization'], 'Bearer at-1');
        return http.Response(
          jsonEncode({
            'models': [
              {'slug': 'gpt-6.1-sol', 'visibility': 'list'},
              {'slug': 'hidden', 'visibility': 'hide'},
              {'slug': 'gpt-5.6-terra', 'visibility': 'list'},
            ],
          }),
          200,
        );
      }),
    );
    await auth.debugSetSession(_session());
    expect(await auth.listModels(), ['gpt-6.1-sol', 'gpt-5.6-terra']);
  });
}
