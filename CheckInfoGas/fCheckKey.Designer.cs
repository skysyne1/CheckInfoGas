namespace CheckInfoGas
{
    partial class fCheckKey
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            tbKey = new System.Windows.Forms.TextBox();
            btnReload = new System.Windows.Forms.Button();
            SuspendLayout();
            // 
            // tbKey
            // 
            tbKey.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
            tbKey.Location = new System.Drawing.Point(122, 66);
            tbKey.Name = "tbKey";
            tbKey.ReadOnly = true;
            tbKey.Size = new System.Drawing.Size(405, 27);
            tbKey.TabIndex = 0;
            // 
            // btnReload
            // 
            btnReload.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
            btnReload.Location = new System.Drawing.Point(242, 113);
            btnReload.Name = "btnReload";
            btnReload.Size = new System.Drawing.Size(94, 36);
            btnReload.TabIndex = 1;
            btnReload.Text = "Reload";
            btnReload.UseVisualStyleBackColor = true;
            btnReload.Click += btnReload_Click;
            // 
            // fCheckKey
            // 
            AutoScaleDimensions = new System.Drawing.SizeF(8F, 20F);
            AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            AutoSize = true;
            ClientSize = new System.Drawing.Size(631, 219);
            Controls.Add(btnReload);
            Controls.Add(tbKey);
            MaximizeBox = false;
            MinimizeBox = false;
            Name = "fCheckKey";
            StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            Text = "fCheckKey";
            Load += fCheckKey_Load;
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private System.Windows.Forms.TextBox tbKey;
        private System.Windows.Forms.Button btnReload;
    }
}