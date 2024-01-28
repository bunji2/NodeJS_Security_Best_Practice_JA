# Node.js セキュリティベストプラクティス（日本語訳）

【原文】
https://nodejs.org/en/guides/security

## 目的

このドキュメントは、現在の[脅威モデル](https://github.com/nodejs/node/security/policy#the-nodejs-threat-model)を拡張し、Node.js アプリケーションをセキュアにする方法に関する広範なガイドラインを提供することを目的とします。

## 本ドキュメントの内容

* ベストプラクティス： ベストプラクティスを見るための簡略化された凝縮された方法。[こちらの問題](https://github.com/nodejs/security-wg/issues/488)や[ガイドライン](https://github.com/goldbergyoni/nodebestpractices)を出発点として使うことができます。このドキュメントは Node.js に特化したものであることにご注意下さい。もしあなたが幅広いものを探しているなら、[OSSF のベストプラクティス](https://github.com/ossf/wg-best-practices-os-developers)を検討してください。
* 攻撃の説明：脅威モデルで言及している攻撃を、（可能であれば）コード例を用いてわかりやすく説明し、文書化すること。
* サードパーティライブラリ：脅威（typosquatting 攻撃、悪意のあるパッケージ...）と、node モジュールの依存関係などに関するベストプラクティスを定義します。


## 脅威リスト

### HTTP サーバーのサービス拒否 (CWE-400)

HTTP リクエストの処理方法によって、アプリケーションが設計された目的に対して利用できなくなる攻撃です。
これらのリクエストは、悪意のある行為者によって意図的に作成される必要はありません。
誤った設定やバグのあるクライアントが、サービス拒否につながるリクエストのパターンをサーバに送信することも可能です。

HTTP リクエストは Node.js HTTP サーバーによって受信され、登録されたリクエストハンドラを介してアプリケーションコードに引き渡されます。
サーバーはリクエストボディの内容を解析しません。
したがって、リクエストハンドラに引き渡された後のボディの内容によって引き起こされる DoS は、アプリケーションコードの責任で正しく処理されるため、Node.js 自体の脆弱性ではありません。

WebServer がソケットエラーを適切に処理することを保証しましょう。
例えば、エラー処理なしで作成したサーバーは DoS に対して脆弱です。

```javascript
const net = require('net');
const server = net.createServer(function (socket) {
  // socket.on('error', console.error) // this prevents the server to crash
  socket.write('Echo server\r\n');
  socket.pipe(socket);
});
server.listen(5000, '0.0.0.0');
```

_不正なリクエスト_ が実行された場合、サーバーはクラッシュする可能性があります。

リクエストの内容に起因しない DoS 攻撃の例として、[Slowloris](https://en.wikipedia.org/wiki/Slowloris_(computer_security)) があります。
この攻撃では、HTTP リクエストはゆっくりと送信され、1 つずつ断片化されます。
完全なリクエストが配信されるまで、サーバーは進行中のリクエスト専用のリソースを占有します。
このようなリクエストが同時に大量に送信されると、同時接続数はすぐに最大に達し、サービス拒否に陥ります。
このように、攻撃はリクエストの内容ではなく、サーバーに送られるリクエストのタイミングとパターンに依存します。

#### 緩和策

* Node.js アプリケーションへのリクエストの受信と転送にリバースプロキシを使用します。リバースプロキシは、DoS 攻撃の効果を押さえる、キャッシュ、ロードバランシング、IP ブラックリストなどを提供することができます。
* サーバーのタイムアウトを正しく設定し、アイドル状態のコネクションや、リクエストの到着が遅すぎるコネクションを切断できるようにします。`http.Server` の様々なタイムアウト、特に `headersTimeout`、`requestTimeout`、`timeout`、`keepAliveTimeout` を参照してください。
* ホストごとのオープンソケット数と総ソケット数を制限します。[http のドキュメント](https://nodejs.org/api/http.html)、特に `agent.maxSockets`、`agent.maxTotalSockets`、`agent.maxFreeSockets`、`server.maxRequestsPerSocket` を参照してください。

### DNS リバインディング (CWE-346)

これは、[--inspectスイッチ](https://nodejs.org/en/guides/debugging-getting-started/)を使用してデバッグ・インスペクターを有効にした状態で実行されている Node.js アプリケーションを標的にできる攻撃です。

ウェブ・ブラウザで開かれたウェブサイトは、WebSocket や HTTP リクエストを行うことができるため、ローカルで実行されているデバッグ・インスペクターを標的にすることができます。
これは通常、最近のブラウザが実装している[同一オリジン・ポリシー](https://nodejs.org/en/guides/debugging-getting-started/)によって防がれ、スクリプトが異なるオリジンからリソースに到達することを禁止しています（つまり、悪意のあるウェブサイトはローカル IP アドレスから要求されたデータを読み取ることができません）。

しかし、DNS のリバインディングにより、攻撃者はリクエストのオリジンを一時的にコントロールし、ローカル IP アドレスから発信されているように見せかけることができます。
これは、ウェブサイトとその IP アドレスを解決するために使用される DNS サーバーの両方を制御することによって行われます。
詳細は [DNS Rebinding wiki](https://en.wikipedia.org/wiki/DNS_rebinding) を参照してください。

#### 緩和策

* `process.on('SIGUSR1',...)` リスナーを明示的に用意することで、_SIGUSR1_ シグナルでデバッガ・ポートでのリッスンを開始しないようにして下さい。
* 本番環境ではインスペクタープロトコルを実行しないでください。

### 権限のないアクターへの機密情報の漏洩 (CWE-552)

カレントディレクトリに含まれるすべてのファイルとフォルダは、パッケージ公開時に npm レジストリにプッシュされます。

この動作を制御する仕組みとして、`.npmignore` や `.gitignore` でブロックリストを定義したり、`package.json` で許可リストを定義する方法が用意されています。

#### 緩和策

* パッケージを公開する前に、必ず内容を確認しましょう。`npm publish --dry-run` を使えば、公開するファイルをすべてリストアップできます。
* 公開しないファイルやフォルダを指定しましょう。`.gitignore` や `.npmignore` といった「無視ファイル」も大切です。これにより公開しないファイルやフォルダを明確にできます。また、`package.json` の [files プロパティ](https://docs.npmjs.com/cli/v8/configuring-npm/package-json#files)はその逆に許可リストを設定することができます。
* 万が一漏洩してしまった場合は、必ず[パッケージを非公開](https://docs.npmjs.com/unpublishing-packages-from-the-registry)にしてください。

### HTTP リクエスト・スマグリング（CWE-444）

これは、2 つの HTTP サーバー（通常はプロキシとNode.jsアプリケーション）が関与する攻撃です。
クライアントが HTTP リクエストを送信すると、まずフロントエンドサーバ（プロキシ）を経由し、その後バックエンドサーバ（アプリケーション）にリダイレクトされます。
フロントエンドとバックエンドが曖昧なHTTPリクエストを異なるように解釈する場合、攻撃者はフロントエンドには見えないがバックエンドには見える悪意のあるメッセージを送る可能性があります。つまり、事実上、そのメッセージはプロキシサーバーを通過し「密輸」(スマグリング) されます。

より詳細な説明と例については [CWE-444](https://cwe.mitre.org/data/definitions/444.html) を参照してください。

この攻撃は、Node.js が (任意の) HTTP サーバと異なる HTTP リクエストを解釈することに依存しているため、攻撃が成功すると、Node.js の脆弱性、フロントエンド・サーバの脆弱性、またはその両方が原因となる可能性があります。Node.js がリクエストを解釈する方法が HTTP 仕様 (RFC7230 を参照) と一致している場合は、Node.js の脆弱性とはみなされません。

#### 緩和策

* HTTP サーバの作成時に [insecureHTTPParser](https://nodejs.org/api/cli.html#--insecure-http-parser) オプションを使用しないで下さい。
* あいまいなリクエストを正規化するようにフロントエンドサーバーを設定しましょう。
* Node.js と選択したフロントエンド・サーバーの両方で、新しい HTTP リクエスト・スマグリングの脆弱性を継続的に監視しましょう。
* HTTP/2 をエンドツーエンドで使用し、可能であれば HTTP ダウングレードを無効にしましょう。

### タイミング攻撃による情報暴露（CWE-208）

これは、例えばアプリケーションがリクエストに応答するまでの時間を計測することで、攻撃者が潜在的にセンシティブな情報を知ることができる攻撃です。この攻撃は Node.js 固有のものではなく、ほとんど全てのランタイムを標的にすることができます。

この攻撃は、アプリケーションがタイミングに敏感な操作(例えば分岐)で秘密を使用する時はいつでも可能です。
典型的なアプリケーションの認証処理を考えてみましょう。
ここで、基本的な認証方法には、電子メールとパスワードが認証情報として含まれています。
ユーザー情報は、理想的には DBMS からユーザーが入力したものから検索さます。
ユーザー情報を取得すると、パスワードはデータベースから取得したユーザー情報と比較されます。
組み込みの文字列比較を使用すると、同じ長さの値に対してより長い時間がかかります。
この比較は、許容範囲内で実行されると、不本意にリクエストの応答時間を増加させます。
リクエストの応答時間を比較することで、攻撃者は大量のリクエストの中からパスワードの長さと値を推測することができます。

#### 緩和策

* crypto API は、定数時間アルゴリズムを使用して、実際のセンシティブ値と予想されるセンシティブ値を比較する関数 `timingSafeEqual` を公開しています。
* パスワードの比較には、ネイティブの crypto モジュールでも使用可能な [scrypt](https://nodejs.org/api/crypto.html#cryptoscryptpassword-salt-keylen-options-callback) を使うことができます。
* より一般的には、可変時間操作での秘密情報の使用は避けましょう。これには、秘密情報での分岐や、攻撃者が同じインフラ（例えば同じクラウドマシン）にいる可能性がある場合、秘密情報をメモリへのインデックスとして使用することが含まれます。JavaScript で定時時間コードを書くのは困難です（JITのせいもあります）。暗号アプリケーションには、組み込みの暗号 API か WebAssembly（ネイティブで実装されていないアルゴリズム用）を使ってください。

### 悪意のあるサードパーティモジュール (CWE-1357)

現在 Node.js では、どんなパッケージでもネットワークアクセスなどの強力なリソースにアクセスできます。
さらに、ファイルシステムにもアクセスできるため、任意のデータを任意の場所に送信できます。

node プロセスで実行されるすべてのコードは、`eval()` (またはそれに相当するもの)を使用することで、追加の任意のコードをロードして実行する能力を持っています。
ファイルシステムへの書き込みアクセスを持つすべてのコードは、ロードされた新しいファイルや既存のファイルに書き込むことで、同じことを達成することができます。

Node.js には、ロードされたリソースが信頼されていいるか否かを判定するための、実験的※1な[ポリシーメカニズム](https://nodejs.org/api/permissions.html#policies)があります。
しかし、このポリシーはデフォルトでは有効になっていません。
一般的なワークフローや npm スクリプトを使用して、依存バージョンを固定し、脆弱性の自動チェックを実行するようにしてください。
パッケージをインストールする前に、このパッケージがメンテナンスされていて、期待するコンテンツがすべて含まれていることを確認してください。
Github のソースコードが公開されているものと同じとは限らないので、node_modules で検証してください。

#### サプライチェーン攻撃

Node.js アプリケーションに対するサプライチェーン攻撃は、依存関係（直接的または推移的）のいずれかが侵害された場合に発生します。
これは、アプリケーションの依存関係の仕様が甘すぎる（望ましくない更新を許してしまう）か、または仕様によくあるタイプミスがある（typosquatting の影響を受けやすい）かのどちらかが原因で起こります。

上流パッケージをコントロールできる攻撃者は、悪意のあるコードを含む新しいバージョンを公開することができます。
Node.js アプリケーションが、どのバージョンを使用するのが安全かについて厳密でないままそのパッケージに依存している場合、パッケージは自動的に最新の悪意のあるバージョンに更新され、アプリケーションを危険にさらす可能性があります。

package.json ファイルで指定される依存関係は、正確なバージョン番号を持つことも、範囲を持つこともできます。
しかし、依存関係を正確なバージョンに固定するとき、その依存関係の推移的な依存関係は、それ自身は固定されません。
このため、アプリケーションは必要としない/予期しないアップデートに対して脆弱なままです。

考えられる攻撃ベクトルには次用のようなものがあります：

* タイポスクワッティング攻撃
* ロックファイルポイズニング
* 不正なメンテナ
* 悪意のあるパッケージ
* 依存関係の混乱

#### 緩和策

* ignore-scripts で npm が任意のスクリプトを実行しないようにします。
  * さらに、npm config set ignore-scripts true でグローバルに無効にすることもできます。
* 依存関係のバージョンを、範囲や変更可能なソースからのバージョンではなく、特定の不変のバージョンに固定します。
* すべての依存関係(直接および推移的)を固定するロックファイルを使用しましょう。
  * [ロックファイルポイズニングに対する緩和策](https://blog.ulisesgascon.com/lockfile-posioned)を使用しましょう。
* [`npm-audit`][]のようなツールを使って、CI により新しい脆弱性のチェックを自動化しましょう。
  * Socket のようなツールを使って静的解析でパッケージを分析し、ネットワークやファイルシステムへのアクセスのような危険な動作を見つけましょう。
* `npm install` の代わりに `npm ci` を使いましょう。これはロックファイルを強制するもので、`package.json` ファイルとの間に不整合があるとエラーになります (`package.json` を優先してロックファイルを黙って無視するのではなく)。
* `package.json` ファイルの依存関係の名前にエラーや誤字がないか、注意深くチェックしてください。

### メモリアクセス違反 (CWE-284)

メモリベースまたはヒープベースの攻撃は、メモリ管理エラーと悪用可能なメモリ・アロケータとの組み合わせに依存します。
すべてのランタイムと同様に、Node.js は、プロジェクトが共有マシン上で実行されている場合、これらの攻撃に対して脆弱です。
セキュア・ヒープを使うことは、ポインターのオーバーランやアンダーランによる機密情報の漏洩を防ぐのに有効です。

残念ながら、セキュア・ヒープは Windows では利用できません。
より詳しい情報は、Node.js の `secure-heapドキュメント`を参照してください。

#### 緩和策

* アプリケーションに応じて `--secure-heap=n` を使用してください（ `n` は割り当てられた最大バイトサイズです）。
* 本番アプリケーションを共有マシンで実行しないでください。

### モンキー・パッチ (CWE-349)

モンキー・パッチとは、実行時にプロパティを変更し、既存の動作を変更することです。
例:

```javascript
// eslint-disable-next-line no-extend-native
Array.prototype.push = function (item) {
  // overriding the global [].push
};
```

#### 緩和策

`--frozen-intrinsics` フラグは、実験的に※1 固定化された本来の「参照」を有効にします。
これは、すべての組み込み JavaScript オブジェクトと関数が再帰的に凍結されることを意味します。
したがって、以下のスニペットは `Array.prototype.push` のデフォルト動作をオーバーライドしません。

```javascript
// eslint-disable-next-line no-extend-native
Array.prototype.push = function (item) {
  // overriding the global [].push
};
// Uncaught:
// TypeError <Object <Object <[Object: null prototype] {}>>>:
// Cannot assign to read only property 'push' of object ''
```

しかしながら、`globalThis` を使用すると、新しいグローバルな定義を行ったり既存のグローバルな定義内容を変更したりできてしまうことには注意が必要です。

### プロトタイプ汚染攻撃 (CWE-1321)

プロトタイプ汚染とは、`__proto_`、`_constructor`、`prototype`、および組み込みのプロトタイプから継承されたその他のプロパティの使用法を悪用して、JavaScript 言語のアイテムを変更したりのプロパティを挿入したりするおそれがあります。

```javascript
const a = { a: 1, b: 2 };
const data = JSON.parse('{"__proto__": { "polluted": true}}');
const c = Object.assign({}, a, data);
console.log(c.polluted); // true
// Potential DoS
const data2 = JSON.parse('{"__proto__": null}');
const d = Object.assign(a, data2);
d.hasOwnProperty('b'); // Uncaught TypeError: d.hasOwnProperty is not a function
```

これは JavaScript 言語から継承された潜在的な脆弱性です。

例:

* [CVE-2022-21824](https://www.cvedetails.com/cve/CVE-2022-21824/) (Node.js)
* [CVE-2018-3721](https://www.cvedetails.com/cve/CVE-2018-3721/) (3rd Party library: Lodash)

#### 緩和策

* [安全でない再帰的マージ](https://gist.github.com/DaniAkash/b3d7159fddcff0a9ee035bd10e34b277#file-unsafe-merge-js)を避けましょう。[CVE-2018-16487](https://www.cve.org/CVERecord?id=CVE-2018-16487) を参照してください。
* 外部/信頼できないリクエストに対する JSON スキーマ検証を実装しましょう。
* `Object.create(null)` を使用して、プロトタイプなしでオブジェクトを作成しましょう。
* プロトタイプを凍結しましょう： `Object.freeze(MyObject.prototype)`。
* `--disable-proto` フラグを使用して、`Object.prototype.__proto__` プロパティを無効にしましょう。
* `Object.hasOwn(obj,keyFromObj)` を使って、プロパティがプロトタイプからではなく、オブジェクトに直接存在することを確認しましょう。
* `Object.prototype.__proto__` のメソッドの使用は避けましょう。

### 制御されない検索パス要素 (CWE-427)

Node.js は[モジュール解決アルゴリズム](https://nodejs.org/api/modules.html#modules_all_together)に従ってモジュールをロードします。
そのため、モジュールが要求（require）されたディレクトリは信頼されていると仮定します。

つまり、以下のようなアプリケーションの動作が想定されます。
以下のようなディレクトリ構造を想定します：

* app/
  * server.js
  * auth.js
  * auth

server.js が `require('./auth')` する場合、モジュール解決アルゴリズムに従い、_auth.js_ ではなく _auth_ がロードされます。

#### 緩和策

実験的な※1[完全性チェックを備えたポリシーメカニズム](https://nodejs.org/api/permissions.html#integrity-checks)を使用することで、上の脅威を回避することができます。
先のディレクトリでは、以下の `policy.json` を使うことができます。

```javascript
{
  "resources": {
    "./app/auth.js": {
      "integrity": "sha256-iuGZ6SFVFpMuHUcJciQTIKpIyaQVigMZlvg9Lx66HV8="
    },
    "./app/server.js": {
      "dependencies": {
        "./auth": "./app/auth.js"
      },
      "integrity": "sha256-NPtLCQ0ntPPWgfVEgX46ryTNpdvTWdQPoZO3kHo0bKI="
    }
  }
}
```

したがって、_auth_ モジュールを要求する場合、システムは整合性を検証し、期待されるものと一致しない場合はエラーを投げます。

```bash
» node --experimental-policy=policy.json app/server.js
node:internal/policy/sri:65
      throw new ERR_SRI_PARSE(str, str[prevIndex], prevIndex);
      ^
SyntaxError [ERR_SRI_PARSE]: Subresource Integrity string "sha256-iuGZ6SFVFpMuHUcJciQTIKpIyaQVigMZlvg9Lx66HV8=%" had an unexpected "%" at position 51
    at new NodeError (node:internal/errors:393:5)
    at Object.parse (node:internal/policy/sri:65:13)
    at processEntry (node:internal/policy/manifest:581:38)
    at Manifest.assertIntegrity (node:internal/policy/manifest:588:32)
    at Module._compile (node:internal/modules/cjs/loader:1119:21)
    at Module._extensions..js (node:internal/modules/cjs/loader:1213:10)
    at Module.load (node:internal/modules/cjs/loader:1037:32)
    at Module._load (node:internal/modules/cjs/loader:878:12)
    at Module.require (node:internal/modules/cjs/loader:1061:19)
    at require (node:internal/modules/cjs/helpers:99:18) {
  code: 'ERR_SRI_PARSE'
}
```

ポリシーの変異を避けるために、常に `--policy-integrity` を使うことを推奨します。

## ※1 本番環境での実験的機能

本番環境での実験的機能の使用は推奨されません。
実験的な機能は、必要に応じて変更を加える可能性があります。
しかし、フィードバックは大いに歓迎します。

## OpenSSF Tools

[OpenSSF](https://openssf.org/) は、特に npm パッケージを公開する予定がある場合に、非常に役立ついくつかのイニシアチブを主導しています。これらの取り組みには、以下のようなものがあります：

* [OpenSSF Scorecard](https://securityscorecards.dev/) は、一連の自動化されたセキュリティ・リスク・チェックを使って、オープンソース・プロジェクトを評価します。あなたのコードベースの脆弱性と依存関係を積極的に評価し、脆弱性を受け入れるかどうかについて、情報に基づいた決定を下すために、これを使うことができます。
* [OpenSSF ベストプラクティスバッジプログラム](https://bestpractices.coreinfrastructure.org/en) プロジェクトは、各ベストプラクティスにどのように準拠しているかを記述することで、自主的に自己認証することができます。これにより、プロジェクトに追加できるバッジが生成されます。
