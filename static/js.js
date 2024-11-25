function downloadAdif(){
    var a = window.document.createElement('a');
    const year = String((new Date()).getFullYear()).padStart(2,'0')
    const month = String((new Date()).getMonth()).padStart(2,'0')+1
    const day = String((new Date()).getDate()).padStart(2,'0')
    var data = `
<BAND:3>40m
<CALL:7>ZZ9FOTW
<MODE:3>FT8
<QSO_DATE:8>${year}${month}${day}
<TIME_ON:4>1234
<EOR>
`;
    a.href = window.URL.createObjectURL(new Blob([data], {type: 'application/octet-stream'}));
    console.log(a.href)
    a.download = 'verification.adif';

    // Append anchor to body.
    document.body.appendChild(a);
    a.click();

    // Remove anchor from body
    document.body.removeChild(a);

    document.getElementById("step1").classList.add("collapsed")
    document.getElementById("step2").classList.remove("collapsed")
    document.getElementById("collapseOne").classList.remove("show")
    document.getElementById("collapseTwo").classList.add("show")
    document.getElementById("step2").scrollIntoView()

    return false
}

function uploadAdif(tq){
    console.log(tq)
    const reader = new FileReader();
    reader.onload = async function(e) {
        const response = await fetch("https://fotw.xyz/verify", {
            method: "POST",
            body: e.target.result
          });
          const errorBox = document.getElementById("uploadfailure")
          const successBox = document.getElementById("uploadsuccess")
          if (!response.ok) {
            
            errorBox.innerText= "Error processing certificate. Ensure you have followed the instructions above and try again.";
            errorBox.style.display = "block"
            successBox.style.display = "none"
            document.getElementById("otpKey").value = "ERROR"
          } else {
            const json = await response.json();
            console.log(json);
            successBox.innerText = "Success. Proceed to the next step."
            errorBox.style.display = "none"
            successBox.style.display = "block"
            document.getElementById("otpCallsign").value = json.callsign
            document.getElementById("otpKey").value = json.secret


            document.getElementById("step2").classList.add("collapsed")
            document.getElementById("step3").classList.remove("collapsed")
            document.getElementById("collapseTwo").classList.remove("show")
            document.getElementById("collapseThree").classList.add("show")

            document.getElementById("step3").scrollIntoView()
            
            
          }
    };
    reader.readAsArrayBuffer(tq.files[0]);
    return false
}