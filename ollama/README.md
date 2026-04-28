# Ollama Image 다운 받는 방법

1. /ollama 하위 모든 파일을 다운 받는다.

2. 다운로드 받은 파일이 있는 위치에서 터미널 실행

3. copy /b ollama-eeve-v1-amd64.tar.\* ollama-eeve-v1-amd64.tar

---

# 1.5GB 분할

split -b 1500m ollama-eeve-v1-amd64.tar ollama-eeve-v1-amd64.tar.

git rm --cached ollama-eeve-v1-amd64.tar
git add ollama-eeve-v1-amd64.tar.\*
git commit -m "Add split tar files (under 2GB each)"
git push origin main

# ollama 폴더 안의 모든 파일을 LFS로 관리하겠다는 설정

git lfs track "ollama/\*"

# fatal: '/Users/sqi/ktgenius/git/drive/.git/index.lock' 파일을 만들 수 없습니다: File exists.

rm -f .git/index.lock

# 폴더 추가

git add ollama/

# .gitattributes 파일도 반드시 함께 추가 (LFS 설정 정보가 담겨 있음)

git add .gitattributes

# 커밋

git commit -m "Add split ollama model files"

# tar 합치기

- window
  copy /b ollama-eeve-v1-amd64.tar.\* ollama-eeve-v1-amd64.tar

- mac
  cat ollama-eeve-v1-amd64.tar.\* > ollama-eeve-v1-amd64.tar
