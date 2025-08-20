# AWS BLEA上でのアプリケーション開発を通して、セキュリティ関連サービスの利用方法とベストプラクティスを学ぶ

BLEA (Baseline Environment on AWS) を活用したエンタープライズレベルのセキュリティ統制を持つ AWS チャットアプリケーション開発。

## 🌟 プロジェクト概要

### 研究テーマ
- **BLEA活用**: AWS公式セキュリティベストプラクティスの深堀
- **CDK統一**: TypeScript Infrastructure as Code によるインフラ構築技術体験
- **エンタープライズ対応**: 本番環境で通用するセキュリティ・ガバナンスの調査

## 🏗️ アーキテクチャ

### システム全体構成
```
┌─────────────────────────────────────────────────────────────┐
│                        アーキテクチャ                        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  ガバナンス      │    │  ゲストシステム   │    │ アプリケーション │
│   ベース        │────│   (BLEA拡張)    │────│  (チャット独自)  │
│ (BLEA提供)      │    │                │    │                │
└─────────────────┘    └─────────────────┘    └─────────────────┘
    (セキュリティ統制)      (基盤インフラ)         (ビジネスロジック)
```

### 機能
```
🔒 ガバナンスベース（BLEA自動提供）:
├── AWS CloudTrail      # API監査ログ
├── AWS Config          # リソース設定監査  
├── AWS Security Hub    # セキュリティ状況統合管理
├── Amazon GuardDuty    # 脅威検知
├── AWS Secrets Manager # 機密情報管理
├── AWS WAF             # Webアプリケーション保護
└── AWS SNS or SMS      # メール通知（セキュリティアラート）

🏗️ ゲストシステム（BLEA + カスタマイズ）:
├── VPC + サブネット設計
├── セキュリティグループ
├── IAMロール・ポリシー（最小権限）
├── KMS暗号化キー
└── ログ集約設定
```

## 🛠️ 技術スタック

### フロントエンド（React + TypeScript）
| 技術 | 用途 | BLEA統合 |
|------|------|-----------|
| **React 18 + TypeScript** | UI フレームワーク | ✅ |
| **AWS Amplify** | AWS SDK統合 | ✅ |
| **Material-UI/Tailwind** | UIコンポーネント | ✅ |
| **React Query** | データフェッチング | ✅ |
| **Socket.io Client** | リアルタイム通信 | ✅ |

### バックエンド（サーバーレス + マネージド）
| サービス | 用途 | BLEA統合 |
|----------|------|-----------|
| **AWS Lambda（Python 3.11）** | API処理 | ✅ X-Ray統合 |
| **Aurora PostgreSQL Serverless v2** | データベース | ✅ 暗号化・監査 |
| **AppSync** | GraphQL + リアルタイム | ✅ WAF保護 |
| **API Gateway** | REST API | ✅ ログ・監視 |
| **Amazon Cognito** | 認証・認可 | ✅ MFA対応 |
| **EventBridge** | イベント駆動 | ✅ 監査ログ |

### インフラ（CDK TypeScript統一）
| 技術 | 用途 | BLEA統合 |
|------|------|-----------|
| **AWS CDK 2.x** | Infrastructure as Code | ✅ |
| **TypeScript** | 型安全な開発 | ✅ |
| **GitHub Actions** | CI/CD | ✅ セキュリティスキャン |

## 📋 主要機能

### 基本チャット機能（BLEA準拠）
| 機能 | 技術実装 | セキュリティ統合 |
|------|----------|------------------|
| **リアルタイムメッセージ** | AppSync Subscriptions | WAF + レート制限 |
| **ルーム管理** | Lambda + Aurora | IAM最小権限 |
| **ユーザー管理** | Cognito + Lambda | MFA + セッション管理 |
| **ファイル共有** | S3 Presigned URL | ウイルススキャン |

### セキュリティ機能（BLEA統制）
| 機能 | BLEA実装 | 自動化レベル |
|------|----------|--------------|
| **脅威検知** | GuardDuty統合 | 完全自動 |
| **設定監査** | Config Rules | 完全自動 |
| **セキュリティ統合管理** | Security Hub | 完全自動 |
| **アクセスログ** | CloudTrail | 完全自動 |
| **暗号化** | KMS統合 | 完全自動 |

## 🗃️ データベース設計

### メインテーブル（Aurora PostgreSQL）
| テーブル名 | 説明 | BLEA統合 |
|-----------|------|----------|
| **users** | ユーザー情報 | ✅ Cognito統合、監査ログ |
| **rooms** | チャットルーム | ✅ アクセス制御、監査ログ |
| **messages** | チャットメッセージ | ✅ パーティション、暗号化 |
| **room_members** | ルームメンバー | ✅ 行レベルセキュリティ |
| **user_sessions** | ユーザーセッション | ✅ セッション監視、自動削除 |
| **file_uploads** | ファイル情報 | ✅ S3統合、ウイルススキャン |
| **security_events** | セキュリティイベント | ✅ Security Hub連携 |

### セキュリティ設計
- **KMS暗号化**: 保存時・転送時の完全暗号化
- **行レベルセキュリティ**: ユーザー単位のデータ分離
- **監査ログ**: 全DML操作の自動記録
- **バックアップ**: Point-in-timeリカバリ有効

## 🚀 セットアップ手順

### 前提条件
- Node.js 18+
- AWS CLI設定済み
- AWS CDK v2インストール済み

### 開発環境セットアップ
```bash
# 1. リポジトリクローン
git clone <repository-url>
cd blea-based-chat-app

# 2. 依存関係インストール
npm install

# 3. CDK設定
npm run build
npm run synth

# 4. パラメータ設定
# parameter.ts を環境に合わせて設定

# 5. BLEA基盤デプロイ
npm run cdk deploy
```

### 設定項目（parameter.ts）
```typescript
export const devParameter = {
  securityNotifyEmail: 'aaa@bbb.com',
  securitySlackWorkspaceId: '',
  securitySlackChannelId: ''
};
```

## 📡 API仕様

### REST API エンドポイント
- **ベースURL**: `https://api.chat-app.example.com/api/v1`
- **認証**: Amazon Cognito JWT Token
- **主要エンドポイント**:
  - `POST /auth/login` - ユーザーログイン
  - `GET /rooms` - ルーム一覧取得
  - `POST /rooms/{room_id}/messages` - メッセージ送信
  - `GET /security/events` - セキュリティイベント取得

### GraphQL API (AppSync)
- **エンドポイント**: `https://graphql.chat-app.example.com/graphql`
- **Subscription**: リアルタイムメッセージ受信
- **セキュリティ機能**: BLEA統合セキュリティイベント管理

詳細なAPI仕様は [docs/aws_chat_app_api_spec.md](docs/aws_chat_app_api_spec.md) を参照。

## 🔒 セキュリティ

### 多層防御（Defense in Depth）
```
┌─────────────────────────────────────────────────────────────┐
│                     BLEA Security Layers                    │
├─────────────────────────────────────────────────────────────┤
│ 🌐 Edge Security    │ CloudFront + WAF              │ Layer 7 │
│ 🔒 API Security     │ API Gateway + Cognito         │ Layer 6 │
│ 🛡️ Network Security │ VPC + Security Groups         │ Layer 3 │
│ 💾 Data Security    │ KMS + RDS Encryption          │ Layer 2 │
│ 👤 Identity Security│ IAM + Least Privilege         │ Layer 1 │
│ 📊 Monitoring       │ GuardDuty + Security Hub      │ All Layers │
└─────────────────────────────────────────────────────────────┘
```

### 自動セキュリティ対応
| イベント | BLEA自動対応 | 通知 |
|----------|--------------|------|
| **不正アクセス試行** | WAF IPブロック | Slack即座通知 |
| **設定ドリフト** | Config自動修復 | Security Hub |
| **脅威検知** | GuardDuty アラート | 管理者メール |
| **権限昇格** | IAM自動無効化 | 緊急Slack通知 |

## 📖 ドキュメント

- [概要設計書](docs/aws_chat_app_overview_design.md) - システム全体アーキテクチャ
- [API仕様書](docs/aws_chat_app_api_spec.md) - REST API / GraphQL 詳細仕様
- [テーブル定義書](docs/aws_chat_app_table_definitions.md) - データベース設計詳細

## 🧪 開発コマンド[]

```bash
# ビルド
npm run build

# テスト実行
npm run test

# CDKテンプレート生成
npm run synth

# CDKデプロイ
npm run cdk deploy

# クリーンアップ
npm run clean
```
