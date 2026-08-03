const API_BASE = "";

const serverStatus = document.querySelector("#serverStatus");
const healthOutput = document.querySelector("#healthOutput");
const refreshHealth = document.querySelector("#refreshHealth");
const runButton = document.querySelector("#runRecommend");
const travelStyle = document.querySelector("#travelStyle");
const region = document.querySelector("#region");
const companion = document.querySelector("#companion");
const chips = document.querySelectorAll(".chip");
const list = document.querySelector("#recommendationList");
const profileName = document.querySelector("#profileName");
const routeTitle = document.querySelector("#routeTitle");
const routeList = document.querySelector("#routeList");
const metricScore = document.querySelector("#metricScore");
const metricPlaces = document.querySelector("#metricPlaces");
const savedPreference = (() => {
  try {
    return JSON.parse(localStorage.getItem("itdaTravelPreference") || "null");
  } catch {
    return null;
  }
})();

async function requestJson(path, options) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options
  });

  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }

  return response.json();
}

function activeKeywords() {
  return [...chips]
    .filter((chip) => chip.classList.contains("active"))
    .map((chip) => chip.dataset.keyword);
}

function applySavedPreference() {
  if (!savedPreference?.type) return;
  travelStyle.value = savedPreference.type;
  if (Array.isArray(savedPreference.keywords)) {
    chips.forEach((chip) => {
      chip.classList.toggle("active", savedPreference.keywords.includes(chip.dataset.keyword));
    });
    if (!activeKeywords().length) {
      chips.forEach((chip) => {
        const fallback = savedPreference.type === "history" ? ["전통"] :
          savedPreference.type === "image" ? ["사진", "야경"] : ["산책", "조용함"];
        chip.classList.toggle("active", fallback.includes(chip.dataset.keyword));
      });
    }
  }
}

async function loadHealth() {
  try {
    const data = await requestJson("/api/health");
    serverStatus.textContent = "API 연결됨";
    serverStatus.className = "server-pill ok";
    healthOutput.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    serverStatus.textContent = "API 연결 실패";
    serverStatus.className = "server-pill fail";
    healthOutput.textContent = JSON.stringify({
      status: "error",
      message: "백엔드가 실행 중인지 확인해주세요.",
      detail: error.message
    }, null, 2);
  }
}

async function loadPlacesCount() {
  try {
    const places = await requestJson("/api/places");
    metricPlaces.textContent = places.length;
  } catch {
    metricPlaces.textContent = "-";
  }
}

function renderRecommendations(data) {
  profileName.textContent = data.profileName;
  metricScore.textContent = `${data.results[0]?.matchScore ?? 0}%`;

  list.innerHTML = data.results.map((item) => `
    <article class="recommendation">
      <div class="score">${item.matchScore}%</div>
      <div>
        <div class="tagline">
          <span>${item.region}</span>
          <span>${item.type}</span>
          ${item.dataSignals.map((signal) => `<span>${signal}</span>`).join("")}
        </div>
        <h3>${item.name}</h3>
        <p>${item.summary}</p>
        <div class="reasons">${item.reasons.join(" · ")}</div>
        <div class="caution">${item.caution}</div>
      </div>
    </article>
  `).join("");
}

function renderRoute(data) {
  routeTitle.textContent = data.title;
  routeList.innerHTML = data.stops.map((stop) => `
    <article class="route-stop">
      <b>${stop.order}</b>
      <time>${stop.time}</time>
      <h3>${stop.place}</h3>
      <p>${stop.region}</p>
      <p>${stop.mission}</p>
    </article>
  `).join("");
}

async function runRecommendation() {
  runButton.disabled = true;
  runButton.textContent = "추천 계산 중";

  const body = {
    travelStyle: travelStyle.value,
    region: region.value,
    companion: companion.value,
    keywords: activeKeywords(),
    mood: travelStyle.value === "rest" ? ["휴식", "조용함"] :
      travelStyle.value === "history" ? ["전통", "문화"] : ["사진", "SNS"],
    limit: 4
  };

  try {
    const data = await requestJson("/api/recommendations", {
      method: "POST",
      body: JSON.stringify(body)
    });
    renderRecommendations(data);

    const route = await requestJson(`/api/itinerary?type=${data.profileType}`);
    renderRoute(route);
  } catch (error) {
    list.innerHTML = `<p class="caution">추천 API 호출에 실패했습니다. ${error.message}</p>`;
  } finally {
    runButton.disabled = false;
    runButton.textContent = "추천 API 실행";
  }
}

chips.forEach((chip) => {
  chip.addEventListener("click", () => chip.classList.toggle("active"));
});

refreshHealth.addEventListener("click", loadHealth);
runButton.addEventListener("click", runRecommendation);
travelStyle.addEventListener("change", runRecommendation);

applySavedPreference();
loadHealth();
loadPlacesCount();
runRecommendation();
