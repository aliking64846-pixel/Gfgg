(() => {
"use strict";
const questions = [
 {q:"في أي جزء من قارة آسيا يقع العراق بحسب الكتاب؟",a:["الشمال الغربي","الجنوب الغربي","الجنوب الشرقي","الشمال الشرقي"],correct:1,why:"يقع العراق في القسم الجنوبي الغربي من قارة آسيا."},
 {q:"بماذا نحدد الموقع الفلكي؟",a:["بالمناخ والتضاريس","بدوائر العرض وخطوط الطول","بالأنهار والجبال","بالسكان والموارد"],correct:1,why:"الموقع الفلكي يحدد باستخدام دوائر العرض وخطوط الطول."},
 {q:"أي دولة تحد العراق من الشمال؟",a:["الكويت","الأردن","تركيا","السعودية"],correct:2,why:"تركيا تقع على الحدود الشمالية للعراق."}
];
let current=0, score=0, answered=false;
const $=s=>document.querySelector(s);
document.querySelectorAll("[data-tab]").forEach(button=>button.addEventListener("click",()=>{
 document.querySelectorAll("[data-tab]").forEach(b=>{b.classList.remove("active");b.setAttribute("aria-selected","false")});
 button.classList.add("active");button.setAttribute("aria-selected","true");
 document.querySelectorAll(".lesson-section").forEach(section=>section.hidden=section.id!==button.dataset.tab);
 if(button.dataset.tab==="quiz" && !$("#question-area").hasChildNodes()) renderQuestion();
}));
function renderQuestion(){
 answered=false;$("#next-question").disabled=true;
 const item=questions[current];const area=$("#question-area");area.replaceChildren();
 const title=document.createElement("div");title.className="quiz-question";title.textContent=(current+1)+". "+item.q;area.append(title);
 const choices=document.createElement("div");choices.className="choices";
 item.a.forEach((answer,index)=>{const btn=document.createElement("button");btn.type="button";btn.className="choice";btn.textContent=answer;btn.addEventListener("click",()=>choose(index,btn,choices,item));choices.append(btn)});
 area.append(choices);const feedback=document.createElement("div");feedback.className="feedback";feedback.id="feedback";feedback.setAttribute("aria-live","polite");area.append(feedback);
 $("#quiz-score").textContent="السؤال "+(current+1)+" من "+questions.length;
 $("#next-question").textContent=current===questions.length-1?"عرض النتيجة":"السؤال التالي ←";
}
function choose(index,button,choices,item){
 if(answered)return;answered=true;
 [...choices.children].forEach((b,i)=>{b.disabled=true;if(i===item.correct)b.classList.add("correct")});
 if(index===item.correct){score++;button.classList.add("correct");$("#feedback").textContent="إجابة صحيحة! "+item.why}
 else{button.classList.add("wrong");$("#feedback").textContent="مو مشكلة، راجع الإجابة المظللة. "+item.why}
 $("#next-question").disabled=false;
}
$("#next-question").addEventListener("click",()=>{
 if(!answered)return;
 if(current<questions.length-1){current++;renderQuestion();return}
 $("#question-area").hidden=true;$("#next-question").hidden=true;$("#quiz-score").hidden=true;
 $("#final-score").textContent="نتيجتك "+score+" / "+questions.length;
 $("#lesson-complete").classList.add("show");
 try{localStorage.setItem("mustaqbali100-social-studies-v1",JSON.stringify({completedCount:score>=2?1:0,completionRate:score>=2?100:0,reviewCount:questions.length-score,lastLesson:"geo-lesson-01",score,updatedAt:new Date().toISOString()}))}catch(e){console.warn("تعذر حفظ التقدم",e)}
});
})();