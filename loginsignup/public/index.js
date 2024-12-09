let input=document.querySelector(".input");
let button=document.querySelector(".button");
let element=document.querySelector(".text");
const form = document.querySelector("form"),
eInput = form.querySelector(".input"),
text = form.querySelector(".text");
form.addEventListener("submit", (e)=>{
  e.preventDefault(); //preventing form from submitting
  let url=`https://www.disify.com/api/email/${input.value}`
    console.log(url);
    result=fetch(url)
    .then(response => response.json())
    .then(data => check(data) )
    .catch(error => console.error('Error:', error));
});
function check(data){
    form.classList.add("error");
    if(data.disposable){
        form.classList.replace("valid" , "error");
        element.innerHTML="This is a disposable Email";
    }else{
        form.classList.replace("error" , "valid");
        element.innerHTML="This is a actual email";
    }
}