# Git Flow Yaklaşımı

Bu doküman, VoyaGo projesinde **Git Flow** çalışma modelinin nasıl kullanılacağını ve **CI/CD entegrasyonunun** bu modele nasıl adapte edileceğini adım adım anlatır. Projeye yeni katılan ekip arkadaşlarının da kolayca takip edebilmesi için tüm temel kavramlar, branch isimlendirme kuralları ve iş akışları Türkçe olarak hazırlanmıştır.

---

## İçindekiler

1. [Genel Bakış](#genel-bakış)
2. [Branch Türleri ve İsimlendirme](#branch-türleri-ve-isimlendirme)
3. [Git Flow İş Akışı](#git-flow-iş-akışı)

   * 3.1. Feature Branch
   * 3.2. Develop Branch
   * 3.3. Release Branch
   * 3.4. Hotfix Branch
4. [CI/CD Entegrasyonu](#cicd-entegrasyonu)
5. [Örnek Komutlar](#örnek-komutlar)
6. [En İyi Uygulamalar](#en-iyi-uygulamalar)

---

## 1. Genel Bakış

**Git Flow**, Vincent Driessen tarafından önerilen ve pek çok modern ekip tarafından tercih edilen bir branching ve release yönetimi modelidir. Temel amacı, **ana** (production) kod ile **geliştirme** (development) kodunu birbirinden net şekilde ayırarak, özellik ekleme, test ve hotfix süreçlerini düzenlemektir.

VoyaGo projesinde Git Flow kullanarak:

* Yenilikleri izole edilmiş feature branch'lerde geliştiririz.
* Develop branch üzerinde sürekli entegrasyon (CI) yaparız.
* Release öncesi stabiliteyi release branch'leri ile sağlar, test ortamına bu branch üzerinden deploy ederiz.
* Production hatalarını hotfix branch ile hızlıca düzeltiriz.

---

## 2. Branch Türleri ve İsimlendirme

| Branch Türü | Amaç                                                     | İsim Şablonu               |
| ----------- | -------------------------------------------------------- | -------------------------- |
| **main**    | Production-ready, canlı ortam kodu                       | `main`                     |
| **develop** | Güncel geliştirme kodu, CI/CD entegrasyonu buradan geçer | `develop`                  |
| **feature** | Yeni özellik, iyileştirme veya deneysel geliştirme       | `feature/<özellik-adı>`    |
| **release** | Yayın adayı branch, test ve son kontroller için          | `release/<sürüm-numarası>` |
| **hotfix**  | Production’da acil düzeltme gereken hatalar için         | `hotfix/<sürüm-numarası>`  |

> **Not:** `<sürüm-numarası>` genellikle `v1.2.0` gibi SemVer (Semantic Versioning) uyumlu olmalıdır.

---

## 3. Git Flow İş Akışı

### 3.1. Feature Branch

1. **Oluşturma:**

   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feature/<özellik-adı>
   ```
2. **Geliştirme:** Kodunuzu yazar, unit testlerinizi ekler, `git add` ve `git commit` ile küçük adımlarla kaydeder.
3. **Paylaşma:** Uzaktaki repoya iter.

   ```bash
   git push origin feature/<özellik-adı>
   ```
4. **PR Açma:** Repository arayüzünde feature branch için `develop` hedefli Pull Request oluşturun. Kod incelemesi (code review) tamamlandığında birleştirin (merge).
5. **Temizlik:** Local ve remote feature branch’ini silin.

   ```bash
   git branch -d feature/<özellik-adı>
   git push origin --delete feature/<özellik-adı>
   ```

### 3.2. Develop Branch

* Tüm feature’lar develop’a merge edildikten sonra, **CI** süreci çalışarak testleri ve kalite kontrollerini yapar.
* Eğer tüm testler başarılıysa, sonraki adıma (release) geçmek için hazır demektir.

### 3.3. Release Branch

1. **Oluşturma:** Develop’dan kararlı bir sürüm çıkarmak istediğinizde:

   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b release/vX.Y.Z
   ```
2. **Hazırlık:** Sürüm numarası, `CHANGELOG.md` güncellemeleri, dokümantasyon ve versiyon bilgisi gibi son rötuşları yapın.
3. **Test ve Onay:** Release branch’ini test ortamına deploy edin ve QA ekibi onayını alsın.
4. **Merge ve Tag:** Onaylandıktan sonra:

   ```bash
   git checkout main
   git pull origin main
   git merge --no-ff release/vX.Y.Z
   git tag -a vX.Y.Z -m "Release vX.Y.Z"

   git checkout develop
   git merge --no-ff release/vX.Y.Z

   git push origin main develop --tags
   ```
5. **Silinme:** Release branch’i silinebilir:

   ```bash
   git branch -d release/vX.Y.Z
   git push origin --delete release/vX.Y.Z
   ```

### 3.4. Hotfix Branch

1. **Oluşturma:** Production’da acil bir düzeltme gerekiyorsa:

   ```bash
   git checkout main
   git pull origin main
   git checkout -b hotfix/vX.Y.Z
   ```
2. **Düzeltme:** Hatanın kaynağını bulun, kodu düzeltin, testleri yazın.
3. **Merge ve Tag:** Düzeltme hazırsa:

   ```bash
   git checkout main
   git merge --no-ff hotfix/vX.Y.Z
   git tag -a vX.Y.Z -m "Hotfix vX.Y.Z"

   git checkout develop
   git merge --no-ff hotfix/vX.Y.Z

   git push origin main develop --tags
   ```
4. **Silinme:**

   ```bash
   git branch -d hotfix/vX.Y.Z
   git push origin --delete hotfix/vX.Y.Z
   ```

---

## 4. CI/CD Entegrasyonu

### Branch Bazlı Trigger’lar

* **feature/**: Pull Request açıldığında kod kalite kontrolleri, unit testler, linter ve security scanning çalışsın.
* **develop**: Her merge sonrası tam CI pipeline (test, integration test, snapshot deploy) tetiklensin.
* **release/**: Merge öncesi smoke test, QA deploy isteğinde staging’e deploy.
* **main**: Merge sonrası production deploy ve tagging işlemleri yapılsın.
* **hotfix/**: Merge sonrası production deploy doğrudan gerçekleşsin.

### Örnek GitHub Actions Workflow (cloudbuild.yaml yerine `.github/workflows/ci.yml`)

```yaml
name: CI/CD Pipeline
on:
  push:
    branches:
      - develop
      - 'release/*'
      - 'hotfix/*'
  pull_request:
    branches:
      - develop

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.23'
      - name: Install dependencies
        run: go mod download
      - name: Run linters
        run: make lint
      - name: Run unit tests
        run: go test ./src/...

  deploy:
    if: github.ref == 'refs/heads/develop' || startsWith(github.ref, 'refs/tags/')
    needs: build-and-test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Deploy to Kubernetes (skaffold)
        run: skaffold run --default-repo=$REGISTRY
        env:
          REGISTRY: ${{ secrets.CONTAINER_REGISTRY }}
```

---

## 5. Örnek Komutlar

| İşlem                      | Komut                                   |
| -------------------------- | --------------------------------------- |
| Yeni feature oluştur       | `git flow feature start <özellik-adı>`  |
| Feature tamamlanınca bitir | `git flow feature finish <özellik-adı>` |
| Yeni release başlat        | `git flow release start vX.Y.Z`         |
| Release tamamlanınca bitir | `git flow release finish vX.Y.Z`        |
| Yeni hotfix başlat         | `git flow hotfix start vX.Y.Z`          |
| Hotfix tamamlanınca bitir  | `git flow hotfix finish vX.Y.Z`         |

> **Not:** [git-flow](https://github.com/nvie/gitflow) eklentisi ile komutları kolaylaştırabilirsiniz.

---

## 6. En İyi Uygulamalar

* **Küçük ve Odaklı Commit’ler:** Daha iyi izlenebilirlik ve geri dönüş kolaylığı için.
* **PR Açıklamaları:** Ne, neden, nasıl sorularına cevap veren detaylı açıklamalar yazın.
* **Kod İnceleme (Code Review):** En az bir başka geliştirici onayı şart.
* **SemVer Uygulaması:** Sürüm numaralarını `MAJOR.MINOR.PATCH` formatında tutun.
* **Ana Codetechleri İzole Etme:** Feature branch’ler sadece ilgili değişimi içermeli.
* **CI Başarısı Öncelikli:** Develop ve main üzerinde merge öncesi CI mutlaka yeşil olmalı.
* **Dokümantasyon Güncelleme:** Yeni özellik eklediğinizde veya sürüm çıkardığınızda `CHANGELOG.md` ve `docs/` klasörünü güncelleyin.

---

Bu rehber, VoyaGo’nun **Git Flow** temelli profesyonel sürüm yönetimi ve **CI/CD** pratiklerini standartlaştırmak için hazırlanmıştır. Tüm ekip üyeleri lütfen bu kılavuzu takip ederek çalışma akışlarını sürdürsün.
