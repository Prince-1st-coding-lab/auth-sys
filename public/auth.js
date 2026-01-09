//sending data for registration 
function register() {//function to register
    let email = document.querySelector('#email');
    let password = document.querySelector('#password');
    let role = document.querySelector('#role');
    const userData = {
    email:email.value,
    password:password.value,
    permission:role.value

}
fetch('/api/register',{
    method:'POST',
    headers:{
        'Content-Type':'application/json'
    },
    body:JSON.stringify(userData)
}).then(Response => Response.json())
.then(data =>{
    console.log(data); 
    email.value=''
    password.value=''
    let message = document.querySelector('.message');
    message.innerHTML = '*'+data.message; 
    message.style.display = 'block'; 
}).catch(Error => console.log('error while fetching ' + Error))
}//end to register

//to log in 
function login() {
    let email_input = document.querySelector('#email-input');
    let password_input = document.querySelector('#password-input');
    let remember_me = document.querySelector('#remember-me');
    const users ={
        email : email_input.value,
        password : password_input.value
    }
    fetch('/api/login',{
        method:'POST',
        headers:{
            'Content-Type':'application/json'
        },
        body:JSON.stringify(users)
    }).then(Response => Response.json())
    .then(data => {
        console.log(data);
        
        let message = document.querySelector('.message');
        message.innerHTML = '*'+ data.message;
        message.style.display = 'block';
        if (data.next_page) {
            localStorage.setItem('token',data.token)
            next_page(data.next_page)
            console.log(localStorage.getItem('token'))
        }
        }).catch(Error => console.log(Error))
    
}

// to the next page
function next_page(next_page) {
    fetch('/api/verify',{
        method:'POST',
        headers:{
            'Authorization':'Bearer '+ localStorage.getItem('token'),
            'Content-Type':'application/json'
        }
    }).then(Response => Response.json())
    .then(data => console.log(data))
    .catch(Error => console.log(Error))

    // window.location.href = next_page;
}