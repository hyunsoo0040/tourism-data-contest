const recommendations = {
  rest: {
    title: "휴식·몰입형 추천 결과",
    phoneType: "당신은<br>휴식·몰입형 여행자",
    phoneDesc: "조용한 산책, 자유로운 공간, 오래 머무는 감정을 선호해요.",
    match: 84,
    text: "기대와 장소 분위기가 높은 수준으로 일치합니다.",
    places: [
      {
        tag: "휴식·몰입 84%",
        title: "조용한 산책형 관광지",
        desc: "혼자 걷기 좋고 주변 분위기가 차분한 장소입니다. 주말 오후에는 방문객이 늘 수 있어 오전 방문을 추천합니다.",
        color: "linear-gradient(135deg,#80ed99,#57cc99,#22577a)"
      },
      {
        tag: "감정 몰입 78%",
        title: "오래 머무는 숲길 코스",
        desc: "짧은 인증보다 머무는 경험이 강한 장소입니다. 휴식 목적의 여행자에게 잘 어울립니다.",
        color: "linear-gradient(135deg,#cdb4db,#90dbf4,#8eecf5)"
      }
    ]
  },
  history: {
    title: "역사·전통형 추천 결과",
    phoneType: "당신은<br>역사·전통형 여행자",
    phoneDesc: "장소에 담긴 이야기와 문화적 맥락을 깊게 경험하고 싶어해요.",
    match: 89,
    text: "스토리와 문화 자원이 기대와 잘 맞습니다.",
    places: [
      {
        tag: "역사·전통 89%",
        title: "문화유산 해설 코스",
        desc: "오디오 가이드와 장소 설명 데이터가 풍부해 배경지식을 함께 쌓기 좋은 관광지입니다.",
        color: "linear-gradient(135deg,#f4a261,#e76f51,#7f5539)"
      },
      {
        tag: "스토리 적합 81%",
        title: "전통 마을 산책지",
        desc: "골목, 건축, 생활문화 요소가 함께 남아 있어 천천히 둘러보기 좋습니다.",
        color: "linear-gradient(135deg,#e9c46a,#bc6c25,#606c38)"
      }
    ]
  },
  image: {
    title: "감성·이미지형 추천 결과",
    phoneType: "당신은<br>감성·이미지형 여행자",
    phoneDesc: "사진으로 남기고 싶은 분위기와 시각적 인상을 중요하게 생각해요.",
    match: 86,
    text: "사진 분위기와 시각 키워드가 기대와 잘 맞습니다.",
    places: [
      {
        tag: "감성·이미지 86%",
        title: "사진 분위기형 관광지",
        desc: "색감, 구도, 배경 요소가 선명해 SNS 공유와 기록 중심 여행에 어울립니다.",
        color: "linear-gradient(135deg,#ffafcc,#bde0fe,#a2d2ff)"
      },
      {
        tag: "포토 스팟 79%",
        title: "빛이 예쁜 수변 산책로",
        desc: "방문 시간에 따라 만족도가 크게 달라져 일몰 전후 방문을 추천합니다.",
        color: "linear-gradient(135deg,#ffb703,#fb8500,#219ebc)"
      }
    ]
  }
};

const menuToggle = document.querySelector(".menu-toggle");
const navMenu = document.querySelector(".nav-menu");
const choices = document.querySelectorAll(".choice");
const resultTitle = document.querySelector("#resultTitle");
const recommendationsTarget = document.querySelector("#recommendations");
const phoneType = document.querySelector("#phoneType");
const phoneDesc = document.querySelector("#phoneDesc");
const phoneMatch = document.querySelector("#phoneMatch");
const matchScore = document.querySelector("#matchScore");
const matchBar = document.querySelector("#matchBar");
const matchText = document.querySelector("#matchText");
const sectionLinks = document.querySelectorAll('.nav-menu a[href^="#"], .mobile-tabs a[href^="#"]');
const trackedSections = [...new Set([...sectionLinks].map((link) => link.getAttribute("href")))]
  .map((href) => document.querySelector(href))
  .filter(Boolean);
const savedPreference = (() => {
  try {
    return JSON.parse(localStorage.getItem("itdaTravelPreference") || "null");
  } catch {
    return null;
  }
})();

function renderRecommendations(type) {
  const data = recommendations[type];

  resultTitle.textContent = data.title;
  phoneType.innerHTML = data.phoneType;
  phoneDesc.textContent = data.phoneDesc;
  phoneMatch.textContent = `${data.match}% match`;
  matchScore.textContent = `${data.match}%`;
  matchBar.style.width = `${data.match}%`;
  matchText.textContent = data.text;

  recommendationsTarget.innerHTML = data.places.map((place) => `
    <div class="place">
      <div class="photo" style="background:${place.color}"></div>
      <div>
        <span class="tag">${place.tag}</span>
        <h4>${place.title}</h4>
        <p>${place.desc}</p>
      </div>
    </div>
  `).join("");
}

menuToggle?.addEventListener("click", () => {
  const isOpen = navMenu.classList.toggle("open");
  menuToggle.setAttribute("aria-expanded", String(isOpen));
  menuToggle.setAttribute("aria-label", isOpen ? "메뉴 닫기" : "메뉴 열기");
});

navMenu?.addEventListener("click", (event) => {
  if (event.target.matches("a")) {
    navMenu.classList.remove("open");
    menuToggle?.setAttribute("aria-expanded", "false");
  }
});

function setActiveSection(sectionId) {
  sectionLinks.forEach((link) => {
    const isActive = link.getAttribute("href") === `#${sectionId}`;
    link.classList.toggle("active", isActive);
    if (isActive) link.setAttribute("aria-current", "location");
    else link.removeAttribute("aria-current");
  });
}

let sectionTicking = false;
function updateActiveSection() {
  const marker = window.scrollY + 150;
  let current = trackedSections[0];

  trackedSections.forEach((section) => {
    if (section.offsetTop <= marker) current = section;
  });

  if (current) setActiveSection(current.id);
  sectionTicking = false;
}

window.addEventListener("scroll", () => {
  if (!sectionTicking) {
    window.requestAnimationFrame(updateActiveSection);
    sectionTicking = true;
  }
}, { passive: true });

sectionLinks.forEach((link) => {
  link.addEventListener("click", () => {
    setActiveSection(link.getAttribute("href").slice(1));
  });
});

const observer = new IntersectionObserver((entries) => {
  entries.forEach((entry) => {
    if (entry.isIntersecting) {
      entry.target.classList.add("visible");
      observer.unobserve(entry.target);
    }
  });
}, { threshold: 0.12 });

document.querySelectorAll(".reveal").forEach((section) => observer.observe(section));

const initialType = recommendations[savedPreference?.type] ? savedPreference.type : "rest";
let activeChoiceIndex = Math.max(0, [...choices].findIndex((choice) => choice.dataset.type === initialType));

function activateChoice(index) {
  activeChoiceIndex = (index + choices.length) % choices.length;
  choices.forEach((choice, choiceIndex) => {
    const isActive = choiceIndex === activeChoiceIndex;
    choice.classList.toggle("active", isActive);
    choice.setAttribute("aria-pressed", String(isActive));
  });
  renderRecommendations(choices[activeChoiceIndex].dataset.type);
}

activateChoice(activeChoiceIndex);
window.setInterval(() => activateChoice(activeChoiceIndex + 1), 3000);
updateActiveSection();
